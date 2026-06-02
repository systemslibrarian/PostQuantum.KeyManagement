using System.Diagnostics.CodeAnalysis;
using System.Text;
using PostQuantum.KeyManagement.Internal;

namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// The non-secret, persistable description of a <see cref="LocalContentKeyProvider"/>'s entire key
/// ring: every KEK's derivation parameters plus which KEK is currently active. Combined with the
/// passphrases (supplied separately at import time), it reconstructs the provider after a restart.
/// </summary>
/// <remarks>
/// <para>
/// This blob contains salts, Argon2id cost parameters, and (in v2+ tokens) a non-secret KEK
/// verifier — never key material or passphrases — so it is safe to store alongside your data.
/// Recovering usable keys still requires the original passphrases via a <see cref="PassphraseResolver"/>.
/// </para>
/// <para>
/// <b>Format versions:</b> v0.4.0-preview.2+ of the library writes <see cref="CurrentFormatVersion"/>
/// (currently 3) tokens that carry a 32-byte per-KEK HMAC-SHA256 verifier. v2 tokens (16-byte
/// truncated verifier, written by 0.3 / 0.4-preview.1) and v1 tokens (no verifier, written by
/// 0.2 and earlier) still decode for backward compatibility. The verifier check at import time
/// is constant-time and compares whatever width the persisted token carries against the matching
/// prefix of the recomputed 32-byte verifier — so v2 keyrings continue to detect wrong passphrases
/// at import under the new reader. v1 tokens still surface a wrong passphrase only at first unwrap,
/// via AES-GCM authentication.
/// </para>
/// </remarks>
public sealed record LocalKeyringMetadata
{
    /// <summary>The format version written by <see cref="Encode"/> on this library version (v3 widens the verifier to 32 bytes).</summary>
    public const byte CurrentFormatVersion = 3;

    private const byte V2FormatVersion = 2;
    private const byte V1FormatVersion = 1;

    /// <summary>
    /// Safety ceiling on the number of KEKs a single token may declare. Production deployments use
    /// a small handful of KEKs; this cap exists purely to defend against malformed input that would
    /// otherwise force a giant allocation.
    /// </summary>
    public const int MaxKekCount = 1024;

    /// <summary>The <see cref="LocalKekMetadata.KeyId"/> of the KEK that was active when exported.</summary>
    public required string ActiveKeyId { get; init; }

    /// <summary>Metadata for every KEK in the ring.</summary>
    public required IReadOnlyList<LocalKekMetadata> Keks { get; init; }

    /// <summary>
    /// Encodes this keyring metadata into a compact, URL-safe Base64 token. Round-trips losslessly
    /// through <see cref="Decode"/>. Always writes the current format version.
    /// </summary>
    public string Encode()
    {
        using var buffer = new MemoryStream();
        buffer.WriteByte(CurrentFormatVersion);
        PortableEncoding.WriteString(buffer, ActiveKeyId);
        PortableEncoding.WriteInt32(buffer, Keks.Count);
        foreach (LocalKekMetadata kek in Keks)
        {
            PortableEncoding.WriteString(buffer, kek.KeyId);
            PortableEncoding.WriteBytes(buffer, kek.Salt);
            PortableEncoding.WriteInt32(buffer, kek.DegreeOfParallelism);
            PortableEncoding.WriteInt32(buffer, kek.MemorySizeInKib);
            PortableEncoding.WriteInt32(buffer, kek.Iterations);
            PortableEncoding.WriteBytes(buffer, kek.Verifier ?? []);
        }

        return PortableEncoding.ToBase64Url(buffer.ToArray());
    }

    /// <summary>Decodes a token produced by <see cref="Encode"/> back into <see cref="LocalKeyringMetadata"/>.</summary>
    /// <exception cref="FormatException">The token is malformed, oversized, or uses an unsupported format version.</exception>
    /// <exception cref="ArgumentException"><paramref name="token"/> is null or empty.</exception>
    public static LocalKeyringMetadata Decode(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        return DecodeCore(token);
    }

    /// <summary>
    /// Attempts to decode a token produced by <see cref="Encode"/>. Returns <see langword="true"/> on
    /// success and assigns the result; returns <see langword="false"/> on any malformed input
    /// without throwing.
    /// </summary>
    /// <remarks>
    /// Use this overload when the token comes from an untrusted source (user input, file content
    /// produced by an older version, network payload) and exception-driven control flow would be
    /// inappropriate. The exception-throwing <see cref="Decode"/> remains the right choice when a
    /// malformed token is a programmer error.
    /// </remarks>
    public static bool TryDecode([NotNullWhen(true)] string? token, [NotNullWhen(true)] out LocalKeyringMetadata? result)
    {
        if (string.IsNullOrEmpty(token))
        {
            result = null;
            return false;
        }

        try
        {
            result = DecodeCore(token);
            return true;
        }
        catch (FormatException)
        {
            result = null;
            return false;
        }
    }

    /// <summary>
    /// Renders a diagnostic-friendly representation showing the active KEK id and KEK count,
    /// without dumping every <see cref="LocalKekMetadata"/> in the ring. Safe to log.
    /// </summary>
    private bool PrintMembers(StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Append("ActiveKeyId = ").Append(ActiveKeyId);
        builder.Append(", Keks.Count = ").Append(Keks.Count);
        return true;
    }

    private static LocalKeyringMetadata DecodeCore(string token)
    {
        byte[] data = PortableEncoding.FromBase64Url(token);
        int offset = 0;

        byte version = PortableEncoding.ReadByte(data, ref offset);
        if (version is not (V1FormatVersion or V2FormatVersion or CurrentFormatVersion))
        {
            throw new FormatException($"Unsupported keyring-metadata format version: {version}.");
        }

        string activeKeyId = PortableEncoding.ReadString(data, ref offset);
        int count = PortableEncoding.ReadInt32(data, ref offset);
        if (count < 0 || count > MaxKekCount)
        {
            throw new FormatException("Corrupt or oversized KEK count in keyring-metadata token.");
        }

        var keks = new List<LocalKekMetadata>(count);
        for (int i = 0; i < count; i++)
        {
            string keyId = PortableEncoding.ReadString(data, ref offset);
            byte[] salt = PortableEncoding.ReadBytes(data, ref offset);
            int parallelism = PortableEncoding.ReadInt32(data, ref offset);
            int memory = PortableEncoding.ReadInt32(data, ref offset);
            int iterations = PortableEncoding.ReadInt32(data, ref offset);
            byte[]? verifier = null;
            if (version >= V2FormatVersion)
            {
                // v2 stored the first 16 bytes of HMAC-SHA256; v3 stores the full 32 bytes.
                // Import compares whatever width is persisted against the matching prefix of the
                // recomputed verifier, in constant time, so both widths are accepted.
                byte[] raw = PortableEncoding.ReadBytes(data, ref offset);
                verifier = raw.Length == 0 ? null : raw;
            }

            keks.Add(new LocalKekMetadata
            {
                KeyId = keyId,
                Salt = salt,
                DegreeOfParallelism = parallelism,
                MemorySizeInKib = memory,
                Iterations = iterations,
                Verifier = verifier,
            });
        }

        return new LocalKeyringMetadata { ActiveKeyId = activeKeyId, Keks = keks };
    }
}
