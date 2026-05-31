using PostQuantum.KeyManagement.Internal;

namespace PostQuantum.KeyManagement;

/// <summary>
/// The encrypted ("wrapped") form of a content key, plus the routing metadata required to unwrap
/// it. Contains no plaintext key material and is safe to persist next to ciphertext.
/// </summary>
public sealed record WrappedContentKey
{
    private const byte FormatVersion = 1;

    /// <summary>The <see cref="IContentKeyProvider.ProviderId"/> of the provider that produced this key.</summary>
    public required string ProviderId { get; init; }

    /// <summary>The identifier of the key-encryption key that wrapped this content key.</summary>
    public required string KeyId { get; init; }

    /// <summary>A human-readable label for the wrapping algorithm (for example, <c>"AES-256-GCM"</c>).</summary>
    public required string Algorithm { get; init; }

    /// <summary>
    /// The opaque wrapped-key blob. Its internal layout is defined by the producing provider; callers
    /// should treat it as an opaque payload.
    /// </summary>
    public required byte[] Ciphertext { get; init; }

    /// <summary>
    /// Encodes this wrapped key into a compact, URL-safe Base64 token suitable for storage or
    /// transport. Round-trips losslessly through <see cref="Decode"/>.
    /// </summary>
    public string Encode()
    {
        using var buffer = new MemoryStream();
        buffer.WriteByte(FormatVersion);
        PortableEncoding.WriteString(buffer, ProviderId);
        PortableEncoding.WriteString(buffer, KeyId);
        PortableEncoding.WriteString(buffer, Algorithm);
        PortableEncoding.WriteBytes(buffer, Ciphertext);
        return PortableEncoding.ToBase64Url(buffer.ToArray());
    }

    /// <summary>Decodes a token produced by <see cref="Encode"/> back into a <see cref="WrappedContentKey"/>.</summary>
    /// <exception cref="FormatException">The token is malformed or uses an unsupported format version.</exception>
    public static WrappedContentKey Decode(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        byte[] data = PortableEncoding.FromBase64Url(token);
        int offset = 0;

        byte version = PortableEncoding.ReadByte(data, ref offset);
        if (version != FormatVersion)
        {
            throw new FormatException($"Unsupported wrapped-key format version: {version}.");
        }

        string providerId = PortableEncoding.ReadString(data, ref offset);
        string keyId = PortableEncoding.ReadString(data, ref offset);
        string algorithm = PortableEncoding.ReadString(data, ref offset);
        byte[] ciphertext = PortableEncoding.ReadBytes(data, ref offset);

        return new WrappedContentKey
        {
            ProviderId = providerId,
            KeyId = keyId,
            Algorithm = algorithm,
            Ciphertext = ciphertext,
        };
    }
}
