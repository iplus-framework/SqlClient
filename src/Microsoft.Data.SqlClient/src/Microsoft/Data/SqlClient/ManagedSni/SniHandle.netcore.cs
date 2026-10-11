// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET

using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClient.ManagedSni
{
    /// <summary>
    /// SNI connection handle
    /// </summary>
    internal abstract class SniHandle
    {
        protected static readonly SslProtocols s_supportedProtocols = SslProtocols.None;

        // iPlus fork: lazily created. SslApplicationProtocol (System.Net.Security) is
        // PlatformNotSupported on browser/WASM, and a static initializer touching it would
        // break type initialization of the whole SniHandle hierarchy there. TDS 8.0 (the
        // only user of ALPN) is not used on browser.
        private static List<SslApplicationProtocol> s_tdsProtocols;

        private static List<SslApplicationProtocol> GetTdsProtocols()
        {
            if (s_tdsProtocols == null)
            {
                s_tdsProtocols = new List<SslApplicationProtocol>(1) { new(TdsEnums.TDS8_Protocol) };
            }
            return s_tdsProtocols;
        }

        protected static async Task AuthenticateAsClientAsync(SslStream sslStream, string serverNameIndication, X509CertificateCollection certificate, CancellationToken token)
        {
            SslClientAuthenticationOptions sslClientOptions = new()
            {
                TargetHost = serverNameIndication,
                ApplicationProtocols = GetTdsProtocols(),
                ClientCertificates = certificate
            };
            await sslStream.AuthenticateAsClientAsync(sslClientOptions, token);
        }

        protected static void AuthenticateAsClient(SslStream sslStream, string serverNameIndication, X509CertificateCollection certificate)
        {
            AuthenticateAsClientAsync(sslStream, serverNameIndication, certificate, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Dispose class
        /// </summary>
        public abstract void Dispose();

        /// <summary>
        /// Set async callbacks
        /// </summary>
        /// <param name="receiveCallback">Receive callback</param>
        /// <param name="sendCallback">Send callback</param>
        public abstract void SetAsyncCallbacks(SniAsyncCallback receiveCallback, SniAsyncCallback sendCallback);

        /// <summary>
        /// iPlus fork (browser WASM): true if this handle's transport completes reads
        /// synchronously (e.g. the sync-XHR tunnel stream). Only then may the MARS demux
        /// be pulled synchronously by a session; async transports must keep the
        /// thread-pool callback + packet-event model.
        /// </summary>
        internal virtual bool SupportsSynchronousReceive => false;

        /// <summary>
        /// Set buffer size
        /// </summary>
        /// <param name="bufferSize">Buffer size</param>
        public abstract void SetBufferSize(int bufferSize);

        /// <summary>
        /// Send a packet synchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <returns>SNI error code</returns>
        public abstract uint Send(SniPacket packet);

        /// <summary>
        /// Send a packet asynchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <returns>SNI error code</returns>
        public abstract uint SendAsync(SniPacket packet);

        /// <summary>
        /// Receive a packet synchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <param name="timeoutInMilliseconds">Timeout in Milliseconds</param>
        /// <returns>SNI error code</returns>
        public abstract uint Receive(out SniPacket packet, int timeoutInMilliseconds);

        /// <summary>
        /// Receive a packet asynchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <returns>SNI error code</returns>
        public abstract uint ReceiveAsync(ref SniPacket packet);

        /// <summary>
        /// Enable SSL
        /// </summary>
        public abstract uint EnableSsl(uint options);

        /// <summary>
        /// Disable SSL
        /// </summary>
        public abstract void DisableSsl();

        /// <summary>
        /// Check connection status
        /// </summary>
        /// <returns>SNI error code</returns>
        public abstract uint CheckConnection();

        /// <summary>
        /// Last handle status
        /// </summary>
        public abstract uint Status { get; }

        /// <summary>
        /// Connection ID
        /// </summary>
        public abstract Guid ConnectionId { get; }

        public virtual int ReserveHeaderSize => 0;

        public abstract SniPacket RentPacket(int headerSize, int dataSize);

        public abstract void ReturnPacket(SniPacket packet);

        /// <summary>
        /// Gets a value that indicates the security protocol used to authenticate this connection.
        /// </summary>
        public virtual SslProtocols ProtocolVersion { get; } = 0;

        #if DEBUG
        /// <summary>
        /// Test handle for killing underlying connection
        /// </summary>
        public abstract void KillConnection();
        #endif
    }
}

#endif
