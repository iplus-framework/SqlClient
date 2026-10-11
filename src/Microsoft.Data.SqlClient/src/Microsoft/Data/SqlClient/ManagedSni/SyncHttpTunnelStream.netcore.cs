// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET && IPLUS_BROWSER

using System;
using System.IO;
using System.Runtime.InteropServices.JavaScript;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClient.ManagedSni
{
    /// <summary>
    /// A full-duplex <see cref="Stream"/> over the iPlus SQL Tunnel HTTP sync shim
    /// (<c>/sqltunnel-sync</c> endpoints on <c>PASqlTunnelHost</c>), implemented with
    /// <b>synchronous XMLHttpRequest</b> via JS interop.
    ///
    /// Rationale (docs/SqlTunnel-OptionB-Implementation.md §7): on the browser main thread
    /// there are no real threads — blocking on an incomplete Task falls back to
    /// <c>Monitor.Wait</c>, which single-threaded WASM rejects (PNSE). A WebSocket message is
    /// a JS macrotask and can only be dispatched when the JS stack is empty, so sync-over-async
    /// network I/O is fundamentally impossible with the WebSocket transport. A synchronous XHR,
    /// by contrast, blocks inside the browser's own networking stack: no .NET threads, no
    /// Monitor.Wait, no event-loop re-entrancy. The deprecation warning is cosmetic.
    ///
    /// Wire format (must match PASqlTunnelHost):
    /// - POST {base}/session            -> 200 {"sessionId": "..."}
    /// - POST {base}/{id}/send          body = raw TDS bytes -> 200
    /// - POST {base}/{id}/recv          -> 200 body = base64 text | 204 no-data (retry) | 410 dead
    /// Base64 is used for the receive direction because synchronous XHR in window context only
    /// supports the '' and 'text' response types (no 'arraybuffer').
    /// </summary>
    internal sealed class SyncHttpTunnelStream : Stream
    {
        /// <summary>Must not exceed the relay's per-poll buffer (16 KB).</summary>
        private const int MaxChunkSize = 16 * 1024;

        private readonly string _baseUrl;
        private string _sessionId;
        private readonly byte[] _receiveBuffer = new byte[MaxChunkSize];
        private int _readPos;
        private int _readLen;
        private bool _disposed;

        public SyncHttpTunnelStream(string baseUrl)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))
            {
                throw new ArgumentNullException(nameof(baseUrl));
            }
            _baseUrl = baseUrl.TrimEnd('/');
        }

        /// <summary>
        /// Opens a relay session (one live SQL Server TCP socket server-side).
        /// Synchronous by design — a single fast XHR; the browser blocks internally.
        /// </summary>
        public void Connect()
        {
            SyncHttpTunnelJs.EnsureShimInstalled();
            _sessionId = SyncHttpTunnelJs.CreateSession(_baseUrl);
            if (string.IsNullOrEmpty(_sessionId))
            {
                throw new IOException("SQL tunnel sync shim: empty session id from " + _baseUrl);
            }
        }

        public override bool CanRead => !_disposed;
        public override bool CanSeek => false;
        public override bool CanWrite => !_disposed;

        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
            // Sends are unbuffered from the caller's perspective; nothing to flush.
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            ValidateArgs(buffer, offset, count);
            if (count == 0)
            {
                return 0;
            }

            // Serve buffered bytes first.
            if (_readPos < _readLen)
            {
                int buffered = Math.Min(count, _readLen - _readPos);
                Buffer.BlockCopy(_receiveBuffer, _readPos, buffer, offset, buffered);
                _readPos += buffered;
                return buffered;
            }

            // Long-poll until the relay returns a chunk. A 204 (no data within the relay's
            // ~1 s hold) just retries — this loop is the "wait", and each iteration is a
            // short blocking XHR, never one long-blocked request.
            while (true)
            {
                string base64 = SyncHttpTunnelJs.Recv(_baseUrl, _sessionId);
                if (base64 == null)
                {
                    continue; // 204: no data yet, retry
                }

                byte[] chunk;
                try
                {
                    chunk = Convert.FromBase64String(base64);
                }
                catch (FormatException e)
                {
                    throw new IOException("SQL tunnel sync shim: invalid base64 payload from relay.", e);
                }

                if (chunk.Length == 0)
                {
                    continue; // defensive: treat empty as no-data
                }

                int n = Math.Min(count, chunk.Length);
                Buffer.BlockCopy(chunk, 0, buffer, offset, n);
                if (chunk.Length > n)
                {
                    // Coalesce the remainder for the next read (TDS reads header/body in
                    // separate, smaller requests).
                    _readLen = Math.Min(chunk.Length - n, MaxChunkSize);
                    _readPos = 0;
                    Buffer.BlockCopy(chunk, n, _receiveBuffer, 0, _readLen);
                }
                Console.WriteLine($"SyncHttpTunnelStream: Read returning {n} of {chunk.Length} bytes (requested {count})");
                return n;
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ValidateArgs(buffer, offset, count);
            if (count == 0)
            {
                return;
            }

            string base64 = Convert.ToBase64String(buffer, offset, count);
            Console.WriteLine($"SyncHttpTunnelStream: Write {count} bytes");
            int status = SyncHttpTunnelJs.Send(_baseUrl, _sessionId, base64);
            if (status != 200)
            {
                throw new IOException($"SQL tunnel sync shim: send failed with HTTP {status} (session dead or relay unreachable).");
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            // The sync XHR completes before returning, so the "async" path is a completed task.
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return Task.FromResult(Read(buffer, offset, count));
        }

#if NETSTANDARD2_0_OR_GREATER || NET
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment))
            {
                return new ValueTask<int>(Read(segment.Array, segment.Offset, segment.Count));
            }

            byte[] temp = new byte[buffer.Length];
            int read = Read(temp, 0, temp.Length);
            temp.AsSpan(0, read).CopyTo(buffer.Span);
            return new ValueTask<int>(read);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment))
            {
                Write(segment.Array, segment.Offset, segment.Count);
            }
            else
            {
                byte[] temp = buffer.ToArray();
                Write(temp, 0, temp.Length);
            }
            return ValueTask.CompletedTask;
        }
#endif

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            if (disposing && _sessionId != null)
            {
                try
                {
                    SyncHttpTunnelJs.DeleteSession(_baseUrl, _sessionId);
                }
                catch
                {
                    // best effort — the relay's idle-timeout cleanup will reap the session
                }
                _sessionId = null;
            }
            base.Dispose(disposing);
        }

        private static void ValidateArgs(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (buffer.Length - offset < count) throw new ArgumentException("Offset and length were out of bounds for the array.");
        }
    }

    /// <summary>
    /// JS interop bindings for the sync-XHR shim. The helper functions are installed on
    /// <c>globalThis.sqlTunnelSync</c> once (self-install via indirect eval so no host-page
    /// script tag is required; if a CSP blocks eval, include the same script manually).
    /// </summary>
    internal static partial class SyncHttpTunnelJs
    {
        private static bool _shimInstalled;

        private const string ShimScript = """
            (function () {
                if (globalThis.sqlTunnelSync) { return; }
                globalThis.sqlTunnelSync = {
                    create: function (baseUrl) {
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', baseUrl + '/session', false);
                        xhr.send(null);
                        if (xhr.status !== 200) { throw new Error('SQL tunnel session failed: HTTP ' + xhr.status); }
                        return JSON.parse(xhr.responseText).sessionId;
                    },
                    send: function (baseUrl, sessionId, base64) {
                        var bin = atob(base64);
                        var bytes = new Uint8Array(bin.length);
                        for (var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', baseUrl + '/' + sessionId + '/send', false);
                        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
                        xhr.send(bytes);
                        return xhr.status;
                    },
                    recv: function (baseUrl, sessionId) {
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', baseUrl + '/' + sessionId + '/recv', false);
                        xhr.send(null);
                        if (xhr.status === 204) { return null; }
                        if (xhr.status !== 200) { throw new Error('SQL tunnel recv failed: HTTP ' + xhr.status); }
                        return xhr.responseText;
                    },
                    deleteSession: function (baseUrl, sessionId) {
                        var xhr = new XMLHttpRequest();
                        xhr.open('DELETE', baseUrl + '/' + sessionId, false);
                        xhr.send(null);
                        return xhr.status;
                    }
                };
            })();
            """;

        public static void EnsureShimInstalled()
        {
            if (_shimInstalled)
            {
                return;
            }

            try
            {
                JsEval(ShimScript);
            }
            catch (JSException e)
            {
                throw new IOException(
                    "SQL tunnel sync shim: could not install the JS helper (globalThis.sqlTunnelSync). " +
                    "If the page's Content-Security-Policy blocks eval, include the helper script manually. " +
                    "See docs/SqlTunnel-OptionB-Implementation.md §7.2.", e);
            }
            _shimInstalled = true;
        }

        [JSImport("globalThis.eval")]
        internal static partial void JsEval(string script);

        [JSImport("globalThis.sqlTunnelSync.create")]
        internal static partial string CreateSession(string baseUrl);

        [JSImport("globalThis.sqlTunnelSync.send")]
        internal static partial int Send(string baseUrl, string sessionId, string base64);

        [JSImport("globalThis.sqlTunnelSync.recv")]
        internal static partial string Recv(string baseUrl, string sessionId);

        [JSImport("globalThis.sqlTunnelSync.deleteSession")]
        internal static partial void DeleteSession(string baseUrl, string sessionId);
    }
}

#endif
