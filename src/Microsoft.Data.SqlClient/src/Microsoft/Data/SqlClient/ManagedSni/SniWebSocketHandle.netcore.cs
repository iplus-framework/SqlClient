// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET

using System;
using System.ComponentModel;
using System.IO;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Microsoft.Data.ProviderBase;
using Microsoft.Data.SqlClient.Internal;

namespace Microsoft.Data.SqlClient.ManagedSni
{
    /// <summary>
    /// SQL Tunnel connection handle: a TDS byte stream carried over a tunnel transport.
    /// The default transport is a WebSocket (<see cref="WebSocketStream"/>); on browser WASM
    /// an HTTP sync-XHR transport (SyncHttpTunnelStream) can be selected via an
    /// <c>http://</c>/<c>https://</c> TunnelUrl (see <see cref="SniProxy"/>). The tunnel endpoint
    /// is a dumb byte relay in front of the real SQL Server; all TDS traffic (prelogin, login,
    /// TLS, data) flows unchanged.
    /// </summary>
    internal sealed class SniWebSocketHandle : SniPhysicalHandle
    {
        private readonly string _tunnelUrl;
        private readonly string _hostNameInCertificate;
        private readonly string _serverCertificateFilename;
        private readonly bool _tlsFirst;
        private readonly object _sendSync = new object();

        private Stream _tunnelStream;
        private Stream _stream;

        /// <summary>
        /// iPlus fork (browser WASM): the sync-XHR tunnel transport completes reads
        /// synchronously, enabling the pull-based MARS demux. The IPLUS_SIMULATE_SYNC_READS
        /// test hook lets desktop reproduce the browser condition via WebSocketStream.
        /// </summary>
        internal override bool SupportsSynchronousReceive
        {
            get
            {
#if IPLUS_BROWSER
                if (_tunnelStream is SyncHttpTunnelStream)
                    return true;
#endif
                return _tunnelStream is WebSocketStream && WebSocketStream.SimulateSyncReads;
            }
        }
        private SslStream _sslStream;
        private SslOverTdsStream _sslOverTdsStream;
        private SniAsyncCallback _receiveCallback;
        private SniAsyncCallback _sendCallback;

        private bool _validateCert = true;
        private int _bufferSize = TdsEnums.DEFAULT_LOGIN_PACKET_SIZE;
        private uint _status = TdsEnums.SNI_UNINITIALIZED;
        private Guid _connectionId = Guid.NewGuid();

        public SniWebSocketHandle(
            string tunnelUrl,
            TimeoutTimer timeout,
            bool tlsFirst,
            string hostNameInCertificate,
            string serverCertificateFilename)
            : this(CreateWebSocketTransport(tunnelUrl, timeout), tunnelUrl, timeout, tlsFirst, hostNameInCertificate, serverCertificateFilename)
        {
        }

        /// <summary>
        /// Creates a tunnel handle over an already-connected transport stream
        /// (e.g. the browser HTTP sync shim stream).
        /// </summary>
        internal SniWebSocketHandle(
            Stream connectedTransport,
            string tunnelUrl,
            TimeoutTimer timeout,
            bool tlsFirst,
            string hostNameInCertificate,
            string serverCertificateFilename)
        {
            using (SqlClientSNIEventScope.Create(nameof(SniWebSocketHandle)))
            {
                _tunnelUrl = tunnelUrl;
                _tlsFirst = tlsFirst;
                _hostNameInCertificate = hostNameInCertificate;
                _serverCertificateFilename = serverCertificateFilename;

                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                    "Connection Id {0}, Opening SQL tunnel over {1}", args0: _connectionId, args1: connectedTransport?.GetType().Name);

                try
                {
                    Initialize(connectedTransport);
                }
                catch (Exception e)
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                        "Connection Id {0}, Exception occurred while opening tunnel: {1}", args0: _connectionId, args1: e?.Message);
                    ReportTunnelSNIError(e);
                }
            }
        }

        private static WebSocketStream CreateWebSocketTransport(string tunnelUrl, TimeoutTimer timeout)
        {
            ClientWebSocket webSocket = new ClientWebSocket();
            using CancellationTokenSource cts = timeout.IsInfinite
                ? new CancellationTokenSource()
                : new CancellationTokenSource(TimeSpan.FromMilliseconds(Math.Max(timeout.MillisecondsRemainingInt, 0)));
            webSocket.ConnectAsync(new Uri(tunnelUrl), cts.Token).ConfigureAwait(false).GetAwaiter().GetResult();
            return new WebSocketStream(webSocket);
        }

        private void Initialize(Stream transport)
        {
            _tunnelStream = transport;

#if IPLUS_BROWSER
            // Browser/WASM: System.Net.Security is PlatformNotSupported, so no
            // SslOverTdsStream/SniSslStream can be created. The connection runs
            // plaintext TDS (prelogin ENCRYPT_NOT_SUP); confidentiality comes from
            // the wss:// (or same-origin HTTP) transport. EnableSsl is never reached
            // in this mode.
#else
            Stream stream = _tunnelStream;
            if (!_tlsFirst)
            {
                _sslOverTdsStream = new SslOverTdsStream(_tunnelStream, _connectionId);
                stream = _sslOverTdsStream;
            }
            _sslStream = new SniSslStream(stream, true, new RemoteCertificateValidationCallback(ValidateServerCertificate));
#endif

            _stream = _tunnelStream;
            _status = TdsEnums.SNI_SUCCESS;
            SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                "Connection Id {0}, SQL tunnel opened successfully.", args0: _connectionId);
        }

        public override void Dispose()
        {
            lock (this)
            {
                if (_sslOverTdsStream != null)
                {
                    _sslOverTdsStream.Dispose();
                    _sslOverTdsStream = null;
                }

                if (_sslStream != null)
                {
                    _sslStream.Dispose();
                    _sslStream = null;
                }

                if (_tunnelStream != null)
                {
                    _tunnelStream.Dispose();
                    _tunnelStream = null;
                }

                _stream = null;
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                    "Connection Id {0}, All streams disposed.", args0: _connectionId);
            }
        }

        public override Guid ConnectionId => _connectionId;

        public override uint Status => _status;

        public override SslProtocols ProtocolVersion
        {
            get
            {
                try
                {
                    return _sslStream.SslProtocol;
                }
                catch
                {
                    return base.ProtocolVersion;
                }
            }
        }

        public override uint EnableSsl(uint options)
        {
            using (SqlClientSNIEventScope.Create(nameof(SniWebSocketHandle)))
            {
                _validateCert = (options & TdsEnums.SNI_SSL_VALIDATE_CERTIFICATE) != 0;

                try
                {
                    if (_tlsFirst)
                    {
                        AuthenticateAsClient(_sslStream, _tunnelUrl, null);
                    }
                    else
                    {
                        _sslStream.AuthenticateAsClient(_tunnelUrl, null, s_supportedProtocols, false);
                    }
                    if (_sslOverTdsStream is not null)
                    {
                        _sslOverTdsStream.FinishHandshake();
                    }
                }
                catch (AuthenticationException aue)
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                        "Connection Id {0}, Authentication exception occurred: {1}", args0: _connectionId, args1: aue?.Message);
                    return ReportTunnelSNIError(aue, SniError.CertificateValidationErrorCode);
                }
                catch (InvalidOperationException ioe)
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                        "Connection Id {0}, Invalid Operation Exception occurred: {1}", args0: _connectionId, args1: ioe?.Message);
                    return ReportTunnelSNIError(ioe);
                }

                _stream = _sslStream;
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                    "Connection Id {0}, SSL enabled successfully.", args0: _connectionId);
                return TdsEnums.SNI_SUCCESS;
            }
        }

        public override void DisableSsl()
        {
            using (SqlClientSNIEventScope.Create(nameof(SniWebSocketHandle)))
            {
                _sslStream.Dispose();
                _sslStream = null;
                _sslOverTdsStream?.Dispose();
                _sslOverTdsStream = null;
                _stream = _tunnelStream;
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                    "Connection Id {0}, SSL Disabled. Communication will continue on the tunnel stream.", args0: _connectionId);
            }
        }

        private bool ValidateServerCertificate(object sender, X509Certificate serverCertificate, X509Chain chain, SslPolicyErrors policyErrors)
        {
            if (!_validateCert)
            {
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                    "Connection Id {0}, Certificate will not be validated.", args0: _connectionId);
                return true;
            }

            // Validate against the SQL Server identity, not the relay's. The relay is a transparent
            // byte pipe; the TLS session inside the tunnel terminates at SQL Server.
            return SniCommon.ValidateSslServerCertificate(_connectionId, _tunnelUrl, _hostNameInCertificate, serverCertificate, _serverCertificateFilename, policyErrors);
        }

        public override void SetBufferSize(int bufferSize)
        {
            _bufferSize = bufferSize;
        }

        public override uint Send(SniPacket packet)
        {
            try
            {
                lock (_sendSync)
                {
                    packet.WriteToStream(_stream);
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                        "Connection Id {0}, Data sent to tunnel stream synchronously", args0: _connectionId);
                    return TdsEnums.SNI_SUCCESS;
                }
            }
            catch (Exception e) when (e is ObjectDisposedException or IOException or InvalidOperationException)
            {
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                    "Connection Id {0}, Exception occurred during send: {1}", args0: _connectionId, args1: e?.Message);
                return ReportTunnelSNIError(e);
            }
        }

        public override uint Receive(out SniPacket packet, int timeoutInMilliseconds)
        {
            SniPacket errorPacket;
            lock (this)
            {
                packet = null;

                if (_tunnelStream == null)
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                        "Connection Id {0}, Tunnel stream is null.", args0: _connectionId);
                    return ReportTunnelSNIError(0, SniCommon.ConnOpenFailedError, Strings.SNI_ERROR_10);
                }

                if (timeoutInMilliseconds <= 0 && timeoutInMilliseconds != -1)
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                        "Connection Id {0}, Error 258, Timeout error occurred.", args0: _connectionId);
                    ReportTunnelSNIError(0, SniCommon.ConnTimeoutError, Strings.SNI_ERROR_11);
                    return TdsEnums.SNI_WAIT_TIMEOUT;
                }

                // Note: per-read timeouts are not supported by the WebSocket transport; reads
                // block until data arrives or the tunnel closes. Cancellation is delivered via
                // attention/cancel packets on the TDS level.
                try
                {
                    packet = RentPacket(headerSize: 0, dataSize: _bufferSize);
                    packet.ReadFromStream(_stream);

                    if (packet.Length == 0)
                    {
                        errorPacket = packet;
                        packet = null;
                        var e = new Win32Exception();
                        SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                            "Connection Id {0}, Win32 exception occurred: {1}", args0: _connectionId, args1: e?.Message);
                        return ReportErrorAndReleasePacket(errorPacket, e.NativeErrorCode, 0, e.Message);
                    }

                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                        "Connection Id {0}, Data read from tunnel stream synchronously", args0: _connectionId);
                    return TdsEnums.SNI_SUCCESS;
                }
                catch (ObjectDisposedException ode)
                {
                    errorPacket = packet;
                    packet = null;
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                        "Connection Id {0}, ObjectDisposedException occurred: {1}", args0: _connectionId, args1: ode?.Message);
                    return ReportErrorAndReleasePacket(errorPacket, ode);
                }
                catch (IOException ioe)
                {
                    errorPacket = packet;
                    packet = null;
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.ERR,
                        "Connection Id {0}, IO exception occurred: {1}", args0: _connectionId, args1: ioe?.Message);
                    return ReportErrorAndReleasePacket(errorPacket, ioe);
                }
            }
        }

        public override void SetAsyncCallbacks(SniAsyncCallback receiveCallback, SniAsyncCallback sendCallback)
        {
            _receiveCallback = receiveCallback;
            _sendCallback = sendCallback;
        }

        public override uint SendAsync(SniPacket packet)
        {
            using (SqlClientSNIEventScope.Create(nameof(SniWebSocketHandle)))
            {
                packet.WriteToStreamAsync(_stream, _sendCallback, SniProviders.TCP_PROV);
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                    "Connection Id {0}, Data sent to tunnel stream asynchronously", args0: _connectionId);
                return TdsEnums.SNI_SUCCESS_IO_PENDING;
            }
        }

        public override uint ReceiveAsync(ref SniPacket packet)
        {
            SniPacket errorPacket;
            packet = RentPacket(headerSize: 0, dataSize: _bufferSize);
            packet.SetAsyncIOCompletionCallback(_receiveCallback);
            try
            {
                packet.ReadFromStreamAsync(_stream);
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                    "Connection Id {0}, Data received from tunnel stream asynchronously", args0: _connectionId);
                return TdsEnums.SNI_SUCCESS_IO_PENDING;
            }
            catch (Exception e) when (e is ObjectDisposedException or IOException or InvalidOperationException)
            {
                errorPacket = packet;
                packet = null;
                return ReportErrorAndReleasePacket(errorPacket, e);
            }
        }

        public override uint CheckConnection()
        {
            try
            {
                if (_tunnelStream == null)
                {
                    return TdsEnums.SNI_ERROR;
                }
            }
            catch (ObjectDisposedException ode)
            {
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SniWebSocketHandle), EventType.INFO,
                    "Connection Id {0}, ObjectDisposedException occurred: {1}", args0: _connectionId, args1: ode?.Message);
                return ReportTunnelSNIError(ode);
            }

            return TdsEnums.SNI_SUCCESS;
        }

#if DEBUG
        public override void KillConnection()
        {
            _tunnelStream?.Dispose();
        }
#endif

        private uint ReportTunnelSNIError(Exception sniException, int nativeErrorCode = 0)
        {
            _status = TdsEnums.SNI_ERROR;
            return SniCommon.ReportSNIError(SniProviders.TCP_PROV, SniCommon.InternalExceptionError, sniException, nativeErrorCode);
        }

        private uint ReportTunnelSNIError(int nativeError, uint sniError, string errorMessage)
        {
            _status = TdsEnums.SNI_ERROR;
            return SniCommon.ReportSNIError(SniProviders.TCP_PROV, nativeError, sniError, errorMessage);
        }

        private uint ReportErrorAndReleasePacket(SniPacket packet, Exception sniException)
        {
            if (packet != null)
            {
                ReturnPacket(packet);
            }
            return ReportTunnelSNIError(sniException);
        }

        private uint ReportErrorAndReleasePacket(SniPacket packet, int nativeError, uint sniError, string errorMessage)
        {
            if (packet != null)
            {
                ReturnPacket(packet);
            }
            return ReportTunnelSNIError(nativeError, sniError, errorMessage);
        }
    }
}

#endif
