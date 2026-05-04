namespace NexConvert.OpenVpnToWireGuard.Models;

/// <summary>
/// Represents a WireGuard configuration file.
/// </summary>
public class WireGuardConfig
{
    // [Interface]
    public string? PrivateKey { get; set; }
    public string? Address { get; set; }
    public List<string> DnsServers { get; set; } = [];
    public int? ListenPort { get; set; }

    // [Peer]
    public string? PublicKey { get; set; }
    public string? PresharedKey { get; set; }
    public string? Endpoint { get; set; }
    public List<string> AllowedIPs { get; set; } = [];
    public int PersistentKeepalive { get; set; } = 25;

    /// <summary>
    /// Renders the WireGuard config as a .conf file string.
    /// </summary>
    public string Render()
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("[Interface]");
        sb.AppendLine($"PrivateKey = {PrivateKey ?? "<PASTE_YOUR_PRIVATE_KEY>"}");

        if (!string.IsNullOrWhiteSpace(Address))
            sb.AppendLine($"Address = {Address}");

        if (DnsServers.Count > 0)
            sb.AppendLine($"DNS = {string.Join(", ", DnsServers)}");

        if (ListenPort.HasValue)
            sb.AppendLine($"ListenPort = {ListenPort}");

        sb.AppendLine();
        sb.AppendLine("[Peer]");
        sb.AppendLine($"PublicKey = {PublicKey ?? "<PASTE_SERVER_PUBLIC_KEY>"}");

        if (!string.IsNullOrWhiteSpace(PresharedKey))
            sb.AppendLine($"PresharedKey = {PresharedKey}");

        if (!string.IsNullOrWhiteSpace(Endpoint))
            sb.AppendLine($"Endpoint = {Endpoint}");

        if (AllowedIPs.Count > 0)
            sb.AppendLine($"AllowedIPs = {string.Join(", ", AllowedIPs)}");

        if (PersistentKeepalive > 0)
            sb.AppendLine($"PersistentKeepalive = {PersistentKeepalive}");

        return sb.ToString().TrimEnd();
    }
}
