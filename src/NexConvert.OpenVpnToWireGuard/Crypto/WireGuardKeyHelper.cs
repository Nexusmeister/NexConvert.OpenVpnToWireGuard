using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace NexConvert.OpenVpnToWireGuard.Crypto;

/// <summary>
/// Generates and handles WireGuard Curve25519 key pairs.
/// WireGuard uses raw 32-byte Curve25519 keys encoded in Base64.
/// </summary>
public static class WireGuardKeyHelper
{
    /// <summary>
    /// Generates a new WireGuard private/public key pair.
    /// </summary>
    public static (string privateKey, string publicKey) GenerateKeyPair()
    {
        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(new SecureRandom()));
        var pair = generator.GenerateKeyPair();

        var privateKey = ((X25519PrivateKeyParameters)pair.Private).GetEncoded();
        var publicKey = ((X25519PublicKeyParameters)pair.Public).GetEncoded();

        return (
            Convert.ToBase64String(privateKey),
            Convert.ToBase64String(publicKey)
        );
    }

    /// <summary>
    /// Derives the public key from an existing Base64-encoded private key.
    /// </summary>
    public static string DerivePublicKey(string base64PrivateKey)
    {
        var privateBytes = Convert.FromBase64String(base64PrivateKey);
        var privateParams = new X25519PrivateKeyParameters(privateBytes);
        var publicParams = privateParams.GeneratePublicKey();
        return Convert.ToBase64String(publicParams.GetEncoded());
    }

    /// <summary>
    /// Attempts to extract the TLS pre-shared key material from an OpenVPN
    /// tls-auth or tls-crypt block.  WireGuard PresharedKey must be 32 bytes;
    /// we SHA-256 the raw key data to produce a stable, deterministic value.
    /// Returns null when no usable key material is found.
    /// </summary>
    public static string? ExtractPresharedKey(string? tlsAuthBlock)
    {
        if (string.IsNullOrWhiteSpace(tlsAuthBlock)) return null;

        // Strip PEM headers and whitespace, grab the first 32+ bytes of key data
        var lines = tlsAuthBlock
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(l => !l.StartsWith('-') && !l.StartsWith('#'))
            .ToList();

        if (lines.Count == 0) return null;

        try
        {
            var rawBytes = lines
                .SelectMany(l => Convert.FromBase64String(l.Trim()))
                .ToArray();

            // SHA-256 to get exactly 32 bytes
            using var sha = System.Security.Cryptography.SHA256.Create();
            var hash = sha.ComputeHash(rawBytes);
            return Convert.ToBase64String(hash);
        }
        catch
        {
            return null;
        }
    }
}
