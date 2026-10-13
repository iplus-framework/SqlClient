// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET

using System;
using System.Text;

namespace Microsoft.Data.SqlClient.ManagedSni
{
    /// <summary>
    /// iPlus fork: tunnel authentication parameters carried as query parameters on the
    /// <c>Tunnel URL</c> connection-string keyword, e.g.
    /// <c>Tunnel URL=http://host:8751/sqltunnel-sync?iplususer=u&amp;ipluspass=p&amp;authtoken=t</c>.
    ///
    /// The parameters are stripped from the URL before it is used for endpoint requests or
    /// the WebSocket handshake, and forwarded to the relay out-of-band:
    /// - <c>authtoken</c> — stage 1 (OAuth-style bearer token), sent as an
    ///   <c>Authorization: Bearer</c> header (WS handshake + every HTTP shim request).
    /// - <c>iplususer</c>/<c>ipluspass</c> — stage 2 (iPlus login), sent as a first auth
    ///   frame message (WebSocket transport) or in the shim session POST body (HTTP sync
    ///   shim). The relay validates them via the iPlus login stack before opening the
    ///   TCP connection to SQL Server.
    ///
    /// Wire contract with <c>PASqlTunnelHost</c> (docs/SqlTunnel-OptionB-Implementation.md §9.21).
    /// </summary>
    internal sealed class TunnelAuthInfo
    {
        /// <summary>Magic prefix of the WebSocket auth frame (first binary message).</summary>
        internal const string Magic = "IPTUNNEL-AUTH1\n";

        /// <summary>Tunnel URL without the auth query string.</summary>
        internal string BaseUrl { get; private set; }

        internal string Token { get; private set; }
        internal string User { get; private set; }
        internal string Password { get; private set; }

        internal bool HasToken => !string.IsNullOrEmpty(Token);
        internal bool HasCredentials => !string.IsNullOrEmpty(User);

        private TunnelAuthInfo()
        {
        }

        /// <summary>
        /// Splits the auth query parameters off the tunnel URL. A URL without a query
        /// string yields an empty auth info (backwards compatible with the unauthenticated
        /// relay).
        /// </summary>
        internal static TunnelAuthInfo Parse(string tunnelUrl)
        {
            TunnelAuthInfo info = new TunnelAuthInfo();
            if (string.IsNullOrEmpty(tunnelUrl))
            {
                info.BaseUrl = tunnelUrl;
                return info;
            }

            int queryStart = tunnelUrl.IndexOf('?');
            if (queryStart < 0)
            {
                info.BaseUrl = tunnelUrl;
                return info;
            }

            info.BaseUrl = tunnelUrl.Substring(0, queryStart);
            foreach (string pair in tunnelUrl.Substring(queryStart + 1).Split('&'))
            {
                if (pair.Length == 0)
                {
                    continue;
                }
                int eq = pair.IndexOf('=');
                string key = eq < 0 ? pair : pair.Substring(0, eq);
                string value = eq < 0 ? "" : Uri.UnescapeDataString(pair.Substring(eq + 1));
                switch (key)
                {
                    case "authtoken":
                        info.Token = value;
                        break;
                    case "iplususer":
                        info.User = value;
                        break;
                    case "ipluspass":
                        info.Password = value;
                        break;
                }
            }
            return info;
        }

        /// <summary>
        /// Builds the WebSocket auth frame: <see cref="Magic"/> followed by a flat JSON
        /// object with the stage-1 token and stage-2 iPlus credentials.
        /// </summary>
        internal byte[] BuildAuthFrame()
        {
            string json = "{\"user\":" + JsonQuote(User ?? "") +
                          ",\"password\":" + JsonQuote(Password ?? "") +
                          ",\"token\":" + JsonQuote(Token ?? "") + "}";
            return Encoding.UTF8.GetBytes(Magic + json);
        }

        private static string JsonQuote(string value)
        {
            StringBuilder sb = new StringBuilder(value.Length + 2);
            sb.Append('"');
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\':
                        sb.Append("\\\\");
                        break;
                    case '"':
                        sb.Append("\\\"");
                        break;
                    case '\n':
                        sb.Append("\\n");
                        break;
                    case '\r':
                        sb.Append("\\r");
                        break;
                    case '\t':
                        sb.Append("\\t");
                        break;
                    default:
                        if (c < 0x20)
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }
    }
}

#endif
