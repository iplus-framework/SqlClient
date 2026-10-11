// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET

using System;

#nullable enable

namespace Microsoft.Data.SqlClient.ManagedSni
{
    /// <summary>
    /// Global SNI settings and status
    /// </summary>
    internal static class SniLoadHandle
    {
        [ThreadStatic]
        private static SniError? s_lastError;

        /// <summary>
        /// Last SNI error
        /// </summary>
        public static SniError LastError
        {
            get
            {
                return s_lastError ??= SniError.Success;
            }

            set
            {
                s_lastError = value;
            }
        }

        /// <summary>
        /// SNI library status
        /// </summary>
        public const uint Status = TdsEnums.SNI_SUCCESS;

        /// <summary>
        /// Encryption options setting
        /// </summary>
        public const EncryptionOptions Options = EncryptionOptions.OFF;

        /// <summary>
        /// Verify client encryption possibility
        /// </summary>
        // TODO: by adding support ENCRYPT_NOT_SUP, it could be calculated.
        // iPlus fork: browser/WASM has no System.Net.Security (SslStream is
        // PlatformNotSupported), so the TDS TLS handshake cannot run there. Reporting
        // no OS encryption support makes TdsParser send ENCRYPT_NOT_SUP in prelogin and
        // skip EnableSsl entirely; confidentiality must come from the transport
        // (wss:// tunnel relay). Only allowed with Encrypt=Optional (Encrypt=False).
#if IPLUS_BROWSER
        public const bool ClientOSEncryptionSupport = false;
#else
        public const bool ClientOSEncryptionSupport = true;
#endif
    }
}

#endif
