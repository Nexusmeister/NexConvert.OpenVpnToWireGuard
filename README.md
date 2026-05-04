# OvpnToWireguard

[![CI](https://github.com/Nexusmeister/NexConvert.OpenVpnToWireGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Nexusmeister/NexConvert.OpenVpnToWireGuard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A .NET 10 CLI tool that converts an OpenVPN `.ovpn` profile into a WireGuard `.conf` file.

## Download

Pre-built self-contained binaries are on the [Releases page](../../releases/latest) — no .NET SDK required.

| Platform | File |
|----------|------|
| Linux x64 | `ovpn-to-wg-linux-x64` |
| macOS ARM64 | `ovpn-to-wg-osx-arm64` |
| Windows x64 | `ovpn-to-wg-win-x64.exe` |

---

## Why?

OpenVPN and WireGuard are different protocols — there is no byte-for-byte equivalence.
This tool automates everything it can (endpoint, routing, DNS, key generation, PSK derivation)
and emits clear placeholder comments for the few things that require manual input
(primarily the server's WireGuard public key, which the VPN admin must supply).

---

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10)

---

## Build

```bash
dotnet build
```

Or publish a self-contained single-file binary:

```bash
# Linux x64
dotnet publish -r linux-x64 -c Release -o ./dist

# macOS arm64
dotnet publish -r osx-arm64 -c Release -o ./dist

# Windows x64
dotnet publish -r win-x64 -c Release -o ./dist
```

---

## Usage

```
NexConvert.OpenVpnToWireGuard <input.ovpn> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Output `.conf` path (default: same name as input) |
| `-g`, `--generate-keys` | Generate a fresh WireGuard key pair (default: `true`) |
| `-k`, `--private-key` | Provide an existing Base64 private key |
| `-s`, `--server-pubkey` | Server WireGuard public key |
| `-a`, `--address` | Client VPN IP address, e.g. `10.8.0.2/24` |
| `-r`, `--route-all` | Route all traffic via VPN (`0.0.0.0/0`) |
| `-d`, `--dns` | Fallback DNS if profile specifies none (default: `1.1.1.1`) |

### Examples

```bash
# Minimal — auto-generate keys, auto-detect everything
dotnet run -- sample.ovpn

# Specify the server public key and client address
dotnet run -- myvpn.ovpn \
  --server-pubkey "BASE64_SERVER_PUBKEY==" \
  --address "10.8.0.5/24" \
  --output wg0.conf

# Use an existing private key, route all traffic
dotnet run -- myvpn.ovpn \
  --private-key "YOUR_EXISTING_PRIVKEY==" \
  --route-all
```

---

## What gets converted automatically

| OpenVPN directive | WireGuard equivalent |
|---|---|
| `remote <host> <port>` | `[Peer] Endpoint` |
| `dhcp-option DNS` | `[Interface] DNS` |
| `redirect-gateway` | `AllowedIPs = 0.0.0.0/0` |
| `route` directives | `[Peer] AllowedIPs` (CIDR) |
| `tls-crypt` / `tls-auth` key | `[Peer] PresharedKey` (SHA-256 of key material) |
| *(auto-generated)* | `[Interface] PrivateKey` |

## What requires manual action

| Item | Reason |
|---|---|
| **Server public key** | WireGuard server must be configured separately; key cannot be derived from `.ovpn` |
| **Client VPN IP** | OpenVPN assigns this dynamically via DHCP; WireGuard needs a static assignment |
| **Cipher / Auth** | WireGuard uses ChaCha20-Poly1305 exclusively — no configuration needed |

---

## Project structure

```
NexConvert.OpenVpnToWireGuard/
├── Program.cs                        # CLI entry-point (System.CommandLine)
├── NexConvert.OpenVpnToWireGuard.csproj
├── sample.ovpn                       # Example profile for testing
└── src/
    ├── Models/
    │   ├── OvpnProfile.cs            # Parsed OVPN data model
    │   └── WireGuardConfig.cs        # WG config model + renderer
    ├── Parsers/
    │   └── OvpnParser.cs             # Full .ovpn parser (inline blocks + directives)
    ├── Converters/
    │   └── OvpnToWireguardConverter.cs  # Conversion logic + ConversionOptions
    └── Crypto/
        └── WireGuardKeyHelper.cs     # Curve25519 key generation (BouncyCastle)
```
