using NexConvert.OpenVpnToWireGuard.Models;

namespace NexConvert.OpenVpnToWireGuard.Parsers;

/// <summary>
/// Parses an OpenVPN (.ovpn) configuration file into an <see cref="OvpnProfile"/>.
/// Handles both inline blocks (&lt;ca&gt;…&lt;/ca&gt;) and file-reference directives.
/// </summary>
public static class OvpnParser
{
    public static OvpnProfile Parse(string content)
    {
        var profile = new OvpnProfile();
        var lines = content.ReplaceLineEndings("\n").Split('\n');

        int i = 0;
        while (i < lines.Length)
        {
            var raw = lines[i].Trim();
            i++;

            // Skip comments and blank lines
            if (string.IsNullOrWhiteSpace(raw) || raw.StartsWith('#') || raw.StartsWith(';'))
                continue;

            // ── Inline block directives ────────────────────────────────────────
            if (raw.StartsWith('<') && !raw.StartsWith("</"))
            {
                var tag = raw.Trim('<', '>');
                var blockLines = new List<string>();
                while (i < lines.Length)
                {
                    var bl = lines[i].Trim();
                    i++;
                    if (bl == $"</{tag}>") break;
                    blockLines.Add(bl);
                }
                var blockContent = string.Join("\n", blockLines);
                ApplyBlock(profile, tag, blockContent);
                continue;
            }

            // ── Single-line directives ─────────────────────────────────────────
            var parts = raw.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            var directive = parts[0].ToLowerInvariant();
            var value = parts.Length > 1 ? parts[1].Trim() : string.Empty;

            switch (directive)
            {
                case "remote":
                    ParseRemote(profile, value);
                    break;

                case "proto":
                    profile.Protocol = value.ToLowerInvariant();
                    break;

                case "ca":
                    if (!string.IsNullOrWhiteSpace(value) && value != "[inline]")
                        profile.CaCert = $"# ca file: {value}";
                    break;

                case "cert":
                    if (!string.IsNullOrWhiteSpace(value) && value != "[inline]")
                        profile.ClientCert = $"# cert file: {value}";
                    break;

                case "key":
                    if (!string.IsNullOrWhiteSpace(value) && value != "[inline]")
                        profile.ClientKey = $"# key file: {value}";
                    break;

                case "tls-auth":
                    if (!string.IsNullOrWhiteSpace(value) && value != "[inline]")
                        profile.TlsAuth = $"# tls-auth file: {value}";
                    break;

                case "tls-crypt":
                    if (!string.IsNullOrWhiteSpace(value) && value != "[inline]")
                        profile.TlsCrypt = $"# tls-crypt file: {value}";
                    break;

                case "route":
                    profile.Routes.Add(value);
                    break;

                case "redirect-gateway":
                    profile.RedirectGateway = true;
                    break;

                case "dhcp-option":
                case "push":
                    ParseDhcpOption(profile, value);
                    break;

                case "cipher":
                    profile.Cipher = value;
                    break;

                case "auth":
                    profile.Auth = value;
                    break;

                default:
                    profile.UnknownDirectives.Add(raw);
                    break;
            }
        }

        return profile;
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static void ApplyBlock(OvpnProfile profile, string tag, string content)
    {
        switch (tag.ToLowerInvariant())
        {
            case "ca":
                profile.CaCert = content;
                break;
            case "cert":
                profile.ClientCert = content;
                break;
            case "key":
                profile.ClientKey = content;
                break;
            case "tls-auth":
                profile.TlsAuth = content;
                break;
            case "tls-crypt":
                profile.TlsCrypt = content;
                break;
        }
    }

    private static void ParseRemote(OvpnProfile profile, string value)
    {
        // remote <host> [port] [proto]
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 1) profile.RemoteHost = parts[0];
        if (parts.Length >= 2 && int.TryParse(parts[1], out var port))
            profile.RemotePort = port;
        if (parts.Length >= 3)
            profile.Protocol = parts[2].ToLowerInvariant();
    }

    private static void ParseDhcpOption(OvpnProfile profile, string value)
    {
        // dhcp-option DNS <ip>
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2 &&
            parts[0].Equals("DNS", StringComparison.OrdinalIgnoreCase))
        {
            profile.DnsServers.Add(parts[1]);
        }
    }
}
