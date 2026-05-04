namespace NexConvert.OpenVpnToWireGuard.Models;

/// <summary>
/// Represents a parsed OpenVPN (.ovpn) profile.
/// </summary>
public class OvpnProfile
{
    // Connection
    public string? RemoteHost { get; set; }
    public int RemotePort { get; set; } = 1194;
    public string Protocol { get; set; } = "udp";

    // Crypto material (raw PEM strings)
    public string? CaCert { get; set; }
    public string? ClientCert { get; set; }
    public string? ClientKey { get; set; }
    public string? TlsAuth { get; set; }
    public string? TlsCrypt { get; set; }

    // Routing
    public List<string> Routes { get; set; } = [];
    public bool RedirectGateway { get; set; }

    // DNS
    public List<string> DnsServers { get; set; } = [];

    // Misc options preserved for reference
    public List<string> UnknownDirectives { get; set; } = [];

    // Cipher / auth (informational – WireGuard does not use these)
    public string? Cipher { get; set; }
    public string? Auth { get; set; }
}
