using NexConvert.OpenVpnToWireGuard.Crypto;
using NexConvert.OpenVpnToWireGuard.Models;

namespace NexConvert.OpenVpnToWireGuard.Converters;

/// <summary>
/// Converts a parsed <see cref="OvpnProfile"/> into a <see cref="WireGuardConfig"/>.
///
/// Protocol mapping notes
/// ──────────────────────
/// OpenVPN and WireGuard are fundamentally different protocols; a 1-to-1
/// automated conversion is not possible for all settings.  This converter
/// handles everything it can automatically and emits clear placeholder
/// comments for the settings that require manual intervention (primarily the
/// server public key, which must be obtained from the WireGuard server admin).
/// </summary>
public static class OvpnToWireguardConverter
{
    public static ConversionResult Convert(OvpnProfile profile, ConversionOptions options)
    {
        var warnings = new List<string>();
        var wg = new WireGuardConfig();

        // ── Key generation ─────────────────────────────────────────────────────
        if (options.GenerateNewKeyPair)
        {
            var (priv, pub) = WireGuardKeyHelper.GenerateKeyPair();
            wg.PrivateKey = priv;
            warnings.Add($"Generated new WireGuard private key. " +
                         $"Corresponding public key (share with server admin): {pub}");
        }
        else if (!string.IsNullOrWhiteSpace(options.ExistingPrivateKey))
        {
            wg.PrivateKey = options.ExistingPrivateKey;
        }
        else
        {
            wg.PrivateKey = "<PASTE_YOUR_WIREGUARD_PRIVATE_KEY>";
            warnings.Add("No private key supplied. Replace the placeholder in [Interface] PrivateKey.");
        }

        // ── Endpoint ───────────────────────────────────────────────────────────
        if (!string.IsNullOrWhiteSpace(profile.RemoteHost))
        {
            wg.Endpoint = $"{profile.RemoteHost}:{profile.RemotePort}";
        }
        else
        {
            warnings.Add("No 'remote' directive found. Set [Peer] Endpoint manually.");
        }

        // ── Server public key ──────────────────────────────────────────────────
        if (!string.IsNullOrWhiteSpace(options.ServerPublicKey))
        {
            wg.PublicKey = options.ServerPublicKey;
        }
        else
        {
            wg.PublicKey = "<PASTE_SERVER_WIREGUARD_PUBLIC_KEY>";
            warnings.Add("Server WireGuard public key is unknown. " +
                         "Ask your VPN admin for 'wg pubkey' output and set [Peer] PublicKey.");
        }

        // ── Pre-shared key (from tls-auth / tls-crypt) ─────────────────────────
        var tlsBlock = profile.TlsCrypt ?? profile.TlsAuth;
        var psk = WireGuardKeyHelper.ExtractPresharedKey(tlsBlock);
        if (psk is not null)
        {
            wg.PresharedKey = psk;
            warnings.Add("Derived PresharedKey from OpenVPN tls-auth/tls-crypt material " +
                         "(SHA-256 of key bytes). The server must be configured with the same PSK.");
        }

        // ── AllowedIPs / routing ───────────────────────────────────────────────
        if (profile.RedirectGateway || options.RouteAllTraffic)
        {
            wg.AllowedIPs.Add("0.0.0.0/0");
            wg.AllowedIPs.Add("::/0");
        }
        else
        {
            // Convert explicit 'route' directives
            foreach (var route in profile.Routes)
            {
                var cidr = RouteToAllowedIp(route);
                if (cidr is not null)
                    wg.AllowedIPs.Add(cidr);
            }

            if (wg.AllowedIPs.Count == 0)
            {
                wg.AllowedIPs.Add("0.0.0.0/0"); // safe default
                warnings.Add("No explicit routes found; defaulting AllowedIPs to 0.0.0.0/0 (route all). " +
                             "Adjust if split-tunnel is desired.");
            }
        }

        // ── DNS ────────────────────────────────────────────────────────────────
        wg.DnsServers.AddRange(profile.DnsServers);

        if (profile.DnsServers.Count == 0 && options.FallbackDns is not null)
        {
            wg.DnsServers.Add(options.FallbackDns);
            warnings.Add($"No DNS servers found in profile; using fallback: {options.FallbackDns}");
        }

        // ── Address ────────────────────────────────────────────────────────────
        if (!string.IsNullOrWhiteSpace(options.ClientAddress))
        {
            wg.Address = options.ClientAddress;
        }
        else
        {
            wg.Address = "<CLIENT_VPN_IP>/32";
            warnings.Add("Client VPN IP address unknown (OpenVPN assigns this dynamically). " +
                         "Set [Interface] Address to the IP your WireGuard server assigns you.");
        }

        // ── Informational warnings about dropped directives ────────────────────
        if (!string.IsNullOrWhiteSpace(profile.Cipher))
            warnings.Add($"OpenVPN cipher '{profile.Cipher}' ignored – WireGuard uses ChaCha20-Poly1305.");

        if (!string.IsNullOrWhiteSpace(profile.Auth))
            warnings.Add($"OpenVPN auth '{profile.Auth}' ignored – WireGuard uses Poly1305 MAC.");

        if (profile.Protocol.Contains("tcp"))
            warnings.Add("OpenVPN TCP mode detected. WireGuard is UDP-only.");

        if (profile.UnknownDirectives.Count > 0)
            warnings.Add($"Ignored {profile.UnknownDirectives.Count} unrecognised directive(s): " +
                         string.Join(", ", profile.UnknownDirectives.Take(5)));

        return new ConversionResult(wg, warnings);
    }

    // ── Route helpers ──────────────────────────────────────────────────────────

    private static string? RouteToAllowedIp(string routeValue)
    {
        // route <network> [netmask] [gateway]
        var parts = routeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return null;

        var network = parts[0];

        if (parts.Length >= 2 && !parts[1].Contains('.') is false)
        {
            // Dotted-decimal netmask → prefix length
            var prefix = MaskToPrefix(parts[1]);
            return prefix.HasValue ? $"{network}/{prefix}" : $"{network}/32";
        }

        // Already CIDR or bare host
        return network.Contains('/') ? network : $"{network}/32";
    }

    private static int? MaskToPrefix(string mask)
    {
        if (!System.Net.IPAddress.TryParse(mask, out var ip)) return null;
        var bytes = ip.GetAddressBytes();
        var bits = 0;
        foreach (var b in bytes)
        {
            var v = b;
            while (v != 0) { bits += v & 1; v >>= 1; }
        }
        return bits;
    }
}

public record ConversionResult(WireGuardConfig Config, List<string> Warnings);

public class ConversionOptions
{
    /// <summary>Automatically generate a fresh WireGuard key pair.</summary>
    public bool GenerateNewKeyPair { get; set; } = true;

    /// <summary>Supply an existing Base64 WireGuard private key instead.</summary>
    public string? ExistingPrivateKey { get; set; }

    /// <summary>The WireGuard public key of the server (must be obtained from admin).</summary>
    public string? ServerPublicKey { get; set; }

    /// <summary>Client VPN address (e.g. "10.8.0.2/24"). OpenVPN assigns this dynamically.</summary>
    public string? ClientAddress { get; set; }

    /// <summary>Route all traffic through VPN (equivalent to redirect-gateway).</summary>
    public bool RouteAllTraffic { get; set; }

    /// <summary>DNS server to use if the profile contains none.</summary>
    public string? FallbackDns { get; set; } = "1.1.1.1";
}
