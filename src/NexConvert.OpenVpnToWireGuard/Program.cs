using System.CommandLine;
using NexConvert.OpenVpnToWireGuard.Converters;
using NexConvert.OpenVpnToWireGuard.Models;
using NexConvert.OpenVpnToWireGuard.Parsers;



// ── CLI definition ─────────────────────────────────────────────────────────────

var inputArg = new Argument<FileInfo>("input")
{
    Description = "Path to the .ovpn profile to convert."
};

var outputOption = new Option<FileInfo?>("--output", "-o")
{
    Description = "Output path for the WireGuard .conf file. " +
                  "Defaults to the same name as the input with a .conf extension."
};

var generateKeysOption = new Option<bool>("--generate-keys", "-g")
{
    Description = "Generate a fresh WireGuard key pair (default: true).",
    DefaultValueFactory = _ => true
};

var privateKeyOption = new Option<string?>("--private-key", "-k")
{
    Description = "Existing Base64 WireGuard private key (skips key generation)."
};

var serverPubKeyOption = new Option<string?>("--server-pubkey", "-s")
{
    Description = "WireGuard public key of the server."
};

var addressOption = new Option<string?>("--address", "-a")
{
    Description = "Client VPN IP address/prefix (e.g. 10.8.0.2/24)."
};

var routeAllOption = new Option<bool>("--route-all", "-r")
{
    Description = "Route all traffic through the VPN (0.0.0.0/0).",
    DefaultValueFactory = _ => false
};

var fallbackDnsOption = new Option<string?>("--dns", "-d")
{
    Description = "Fallback DNS server if the profile specifies none.",
    DefaultValueFactory = _ => "1.1.1.1"
};

var rootCommand = new RootCommand(
    "OvpnToWireguard – Converts an OpenVPN .ovpn profile to a WireGuard .conf file.")
{
    inputArg,
    outputOption,
    generateKeysOption,
    privateKeyOption,
    serverPubKeyOption,
    addressOption,
    routeAllOption,
    fallbackDnsOption,
};

rootCommand.SetAction((parseResult) =>
{
    var input        = parseResult.GetValue(inputArg)!;
    var output       = parseResult.GetValue(outputOption);
    var generateKeys = parseResult.GetValue(generateKeysOption);
    var privateKey   = parseResult.GetValue(privateKeyOption);
    var serverPubKey = parseResult.GetValue(serverPubKeyOption);
    var address      = parseResult.GetValue(addressOption);
    var routeAll     = parseResult.GetValue(routeAllOption);
    var fallbackDns  = parseResult.GetValue(fallbackDnsOption);

    // ── Validate input ─────────────────────────────────────────────────────
    if (!input.Exists)
    {
        Console.Error.WriteLine($"[ERROR] File not found: {input.FullName}");
        return 1;
    }

    Console.WriteLine($"[*] Reading: {input.FullName}");
    var ovpnContent = File.ReadAllText(input.FullName);

    // ── Parse ──────────────────────────────────────────────────────────────
    Console.WriteLine("[*] Parsing OpenVPN profile…");
    OvpnProfile profile;
    try
    {
        profile = OvpnParser.Parse(ovpnContent);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[ERROR] Failed to parse profile: {ex.Message}");
        return 2;
    }

    PrintProfileSummary(profile);

    // ── Convert ────────────────────────────────────────────────────────────
    Console.WriteLine("[*] Converting to WireGuard…");

    var options = new ConversionOptions
    {
        GenerateNewKeyPair = string.IsNullOrWhiteSpace(privateKey) && generateKeys,
        ExistingPrivateKey = privateKey,
        ServerPublicKey = serverPubKey,
        ClientAddress = address,
        RouteAllTraffic = routeAll,
        FallbackDns = fallbackDns,
    };

    var result = OvpnToWireguardConverter.Convert(profile, options);

    // ── Warnings ───────────────────────────────────────────────────────────
    if (result.Warnings.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine("── Conversion Notes ──────────────────────────────────────────");
        foreach (var w in result.Warnings)
            Console.WriteLine($"  [!] {w}");
        Console.WriteLine();
    }

    // ── Write output ───────────────────────────────────────────────────────
    var outPath = output?.FullName
        ?? Path.ChangeExtension(input.FullName, ".conf");

    var rendered = result.Config.Render();
    File.WriteAllText(outPath, rendered + Environment.NewLine);

    Console.WriteLine($"[✓] WireGuard config written to: {outPath}");
    Console.WriteLine();
    Console.WriteLine("── Preview ───────────────────────────────────────────────────");
    Console.WriteLine(rendered);
    Console.WriteLine();

    return 0;
});

return await rootCommand.Parse(args).InvokeAsync();

// ── Helpers ────────────────────────────────────────────────────────────────────

static void PrintProfileSummary(OvpnProfile p)
{
    Console.WriteLine();
    Console.WriteLine("── Parsed OpenVPN Profile ────────────────────────────────────");
    Console.WriteLine($"  Remote   : {p.RemoteHost ?? "(none)"}:{p.RemotePort} ({p.Protocol})");
    Console.WriteLine($"  CA       : {(p.CaCert is not null ? "present" : "missing")}");
    Console.WriteLine($"  Cert     : {(p.ClientCert is not null ? "present" : "missing")}");
    Console.WriteLine($"  Key      : {(p.ClientKey is not null ? "present" : "missing")}");
    Console.WriteLine($"  TLS-Auth : {(p.TlsAuth is not null ? "present" : "none")}");
    Console.WriteLine($"  TLS-Crypt: {(p.TlsCrypt is not null ? "present" : "none")}");
    Console.WriteLine($"  DNS      : {(p.DnsServers.Count > 0 ? string.Join(", ", p.DnsServers) : "none")}");
    Console.WriteLine($"  Routes   : {(p.Routes.Count > 0 ? string.Join(", ", p.Routes) : "none")}");
    Console.WriteLine($"  Redir GW : {p.RedirectGateway}");
    Console.WriteLine();
}
