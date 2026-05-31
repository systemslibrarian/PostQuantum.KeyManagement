using PostQuantum.KeyManagement.Internal;

namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// The non-secret, persistable description of a <see cref="LocalContentKeyProvider"/>'s entire key
/// ring: every KEK's derivation parameters plus which KEK is currently active. Combined with the
/// passphrases (supplied separately at import time), it reconstructs the provider after a restart.
/// </summary>
/// <remarks>
/// This blob contains salts and Argon2id cost parameters only — never key material or passphrases —
/// so it is safe to store alongside your data. Recovering usable keys still requires the original
/// passphrases via a <see cref="PassphraseResolver"/>.
/// </remarks>
public sealed record LocalKeyringMetadata
{
    private const byte FormatVersion = 1;

    /// <summary>The <see cref="LocalKekMetadata.KeyId"/> of the KEK that was active when exported.</summary>
    public required string ActiveKeyId { get; init; }

    /// <summary>Metadata for every KEK in the ring.</summary>
    public required IReadOnlyList<LocalKekMetadata> Keks { get; init; }

    /// <summary>
    /// Encodes this keyring metadata into a compact, URL-safe Base64 token. Round-trips losslessly
    /// through <see cref="Decode"/>.
    /// </summary>
    public string Encode()
    {
        using var buffer = new MemoryStream();
        buffer.WriteByte(FormatVersion);
        PortableEncoding.WriteString(buffer, ActiveKeyId);
        PortableEncoding.WriteInt32(buffer, Keks.Count);
        foreach (LocalKekMetadata kek in Keks)
        {
            PortableEncoding.WriteString(buffer, kek.KeyId);
            PortableEncoding.WriteBytes(buffer, kek.Salt);
            PortableEncoding.WriteInt32(buffer, kek.DegreeOfParallelism);
            PortableEncoding.WriteInt32(buffer, kek.MemorySizeInKib);
            PortableEncoding.WriteInt32(buffer, kek.Iterations);
        }

        return PortableEncoding.ToBase64Url(buffer.ToArray());
    }

    /// <summary>Decodes a token produced by <see cref="Encode"/> back into <see cref="LocalKeyringMetadata"/>.</summary>
    /// <exception cref="FormatException">The token is malformed or uses an unsupported format version.</exception>
    public static LocalKeyringMetadata Decode(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        byte[] data = PortableEncoding.FromBase64Url(token);
        int offset = 0;

        byte version = PortableEncoding.ReadByte(data, ref offset);
        if (version != FormatVersion)
        {
            throw new FormatException($"Unsupported keyring-metadata format version: {version}.");
        }

        string activeKeyId = PortableEncoding.ReadString(data, ref offset);
        int count = PortableEncoding.ReadInt32(data, ref offset);
        if (count < 0)
        {
            throw new FormatException("Corrupt KEK count in keyring-metadata token.");
        }

        var keks = new List<LocalKekMetadata>(Math.Min(count, 64));
        for (int i = 0; i < count; i++)
        {
            keks.Add(new LocalKekMetadata
            {
                KeyId = PortableEncoding.ReadString(data, ref offset),
                Salt = PortableEncoding.ReadBytes(data, ref offset),
                DegreeOfParallelism = PortableEncoding.ReadInt32(data, ref offset),
                MemorySizeInKib = PortableEncoding.ReadInt32(data, ref offset),
                Iterations = PortableEncoding.ReadInt32(data, ref offset),
            });
        }

        return new LocalKeyringMetadata { ActiveKeyId = activeKeyId, Keks = keks };
    }
}
