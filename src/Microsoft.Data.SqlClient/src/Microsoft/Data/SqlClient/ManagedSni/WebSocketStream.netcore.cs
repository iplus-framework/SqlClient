// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET

using System;
using System.IO;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClient.ManagedSni
{
    /// <summary>
    /// A full-duplex <see cref="Stream"/> over a <see cref="ClientWebSocket"/> connection.
    ///
    /// Used by the SQL Tunnel transport (browser WASM and other environments without raw TCP
    /// sockets). Every write is sent as one binary WebSocket message; reads coalesce received
    /// binary messages into a buffer so the TDS parser can consume arbitrary byte counts.
    /// The relay on the other side of the WebSocket is a dumb byte pipe (it forwards the raw
    /// payload of every message to the SQL Server TCP socket in order), so message boundaries
    /// never reach the TDS protocol.
    /// </summary>
    internal sealed class WebSocketStream : Stream
    {
        private const int ReceiveBufferSize = 64 * 1024;

        private readonly ClientWebSocket _webSocket;
        private readonly byte[] _receiveBuffer = new byte[ReceiveBufferSize];
        private static readonly bool _simulateSyncReads =
            Environment.GetEnvironmentVariable("IPLUS_SIMULATE_SYNC_READS") == "1";

        /// <summary>iPlus fork test hook: see _simulateSyncReads.</summary>
        internal static bool SimulateSyncReads => _simulateSyncReads;
        private int _readPos;
        private int _readLen;
        private bool _disposed;

        public WebSocketStream(ClientWebSocket webSocket)
        {
            _webSocket = webSocket ?? throw new ArgumentNullException(nameof(webSocket));
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
            // WebSocket sends are unbuffered from the caller's perspective; nothing to flush.
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            ValidateArgs(buffer, offset, count);
            return ReadInternal(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateArgs(buffer, offset, count);
            // iPlus fork (test hook): simulate the browser sync-XHR transport, whose ReadAsync
            // always completes synchronously. Set IPLUS_SIMULATE_SYNC_READS=1 to reproduce the
            // single-threaded-WASM MARS condition on desktop for debugging.
            if (_simulateSyncReads)
            {
                return Task.FromResult(ReadInternal(buffer, offset, count, cancellationToken).GetAwaiter().GetResult());
            }
            return ReadInternal(buffer, offset, count, cancellationToken);
        }

#if NETSTANDARD2_0_OR_GREATER || NET
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.IsEmpty)
            {
                return 0;
            }

            // Serve from the coalescing buffer first; otherwise receive directly into the
            // caller's memory when it is large enough, avoiding an extra copy.
            if (_readPos < _readLen)
            {
                int buffered = Math.Min(buffer.Length, _readLen - _readPos);
                _receiveBuffer.AsSpan(_readPos, buffered).CopyTo(buffer.Span);
                _readPos += buffered;
                return buffered;
            }

            if (buffer.Length >= ReceiveBufferSize)
            {
                return await ReceiveInto(buffer, cancellationToken).ConfigureAwait(false);
            }

            return await ReadInternal(buffer.ToArray(), 0, buffer.Length, cancellationToken).ConfigureAwait(false);
        }
#endif

        private async Task<int> ReadInternal(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
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

            if (count >= ReceiveBufferSize)
            {
                return await ReceiveInto(buffer.AsMemory(offset, count), cancellationToken).ConfigureAwait(false);
            }

            // Receive into the internal buffer, then copy out.
            _readLen = await ReceiveInto(_receiveBuffer, cancellationToken).ConfigureAwait(false);
            _readPos = 0;
            if (_readLen == 0)
            {
                return 0;
            }

            int copied = Math.Min(count, _readLen);
            Buffer.BlockCopy(_receiveBuffer, 0, buffer, offset, copied);
            _readPos = copied;
            return copied;
        }

        /// <summary>
        /// Receives WebSocket binary messages until at least one byte is available, coalescing
        /// them into <paramref name="destination"/>. Returns 0 when the remote end closes.
        /// </summary>
        private async Task<int> ReceiveInto(Memory<byte> destination, CancellationToken cancellationToken)
        {
            int total = 0;
            while (total == 0)
            {
                if (_webSocket.CloseStatus.HasValue)
                {
                    return 0;
                }

                ValueWebSocketReceiveResult result = await _webSocket.ReceiveAsync(destination.Slice(total), cancellationToken).ConfigureAwait(false);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    return 0;
                }

                total += result.Count;

                // Continue receiving while the remote end fragments one logical message or sends
                // back-to-back messages smaller than our destination.
                while (!result.EndOfMessage && total < destination.Length)
                {
                    result = await _webSocket.ReceiveAsync(destination.Slice(total), cancellationToken).ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        return total;
                    }
                    total += result.Count;
                }
            }

            return total;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ValidateArgs(buffer, offset, count);
            WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateArgs(buffer, offset, count);
            await _webSocket.SendAsync(new ArraySegment<byte>(buffer, offset, count), WebSocketMessageType.Binary, endOfMessage: true, cancellationToken).ConfigureAwait(false);
        }

#if NETSTANDARD2_0_OR_GREATER || NET
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            _webSocket.SendAsync(buffer, WebSocketMessageType.Binary, endOfMessage: true, cancellationToken);
#endif

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;

            if (disposing)
            {
                CloseGracefully().GetAwaiter().GetResult();
                _webSocket.Dispose();
            }
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            await CloseGracefully().ConfigureAwait(false);
            _webSocket.Dispose();
            await base.DisposeAsync().ConfigureAwait(false);
        }

        /// <summary>
        /// Sends a close frame so the remote end (the tunnel relay) observes a proper close
        /// instead of an abrupt EOF. Best effort: never throws, bounded by a short timeout.
        /// </summary>
        private async Task CloseGracefully()
        {
            try
            {
                if (_webSocket.State == WebSocketState.Open)
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await _webSocket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, cts.Token).ConfigureAwait(false);
                }
            }
            catch
            {
                // Best effort — the transport is being torn down anyway.
            }
        }

        private void ValidateArgs(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
            {
                throw new ArgumentOutOfRangeException(offset < 0 ? nameof(offset) : nameof(count));
            }
        }
    }
}

#endif
