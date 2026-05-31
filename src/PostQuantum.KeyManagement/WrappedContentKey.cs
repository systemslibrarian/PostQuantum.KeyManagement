using System.Diagnostics.CodeAnalysis;
using System.Text;
using PostQuantum.KeyManagement.Internal;

namespace PostQuantum.KeyManagement;

/// <summary>
/// The encrypted ("wrapped") form of a content key, plus the routing metadata required to unwrap
/// it. Contains no plaintext key material and is safe to persist next to ciphertext.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="Ciphertext"/> property carries a provider-specific blob (for the local provider:
/// <c>nonce || tag || ciphertext</c>). Treat the array as immutable; the library does not defensively
/// copy it on every operation. <see cref="Encode"/> / <see cref="Decode"/> always allocate fresh
/// arrays, so values round-tripped through a token are safe to retain.
/// </para>
/// <para>
/// <see cref="Decode"/> defends against malformed tokens by capping every length-prefixed field at
/// <see cref="PortableEncoding.MaxFieldLength"/> and using overflow-safe bounds arithmetic, so a
/// hostile token cannot trigger huge allocations or out-of-bounds reads.
/// </para>
/// </remarks>
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
    /// <exception cref="ArgumentException"><paramref name="token"/> is null or empty.</exception>
    public static WrappedContentKey Decode(string token)
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
    /// Use this overload when the token comes from an untrusted source (user input, network
    /// payload) and exception-driven control flow would be inappropriate. The exception-throwing
    /// <see cref="Decode"/> remains the right choice when a malformed token is a programmer error.
    /// </remarks>
    public static bool TryDecode([NotNullWhen(true)] string? token, [NotNullWhen(true)] out WrappedContentKey? result)
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
    /// Renders a diagnostic-friendly representation that names the routing fields but never the
    /// ciphertext bytes. Safe to log. Overrides the record's default <c>PrintMembers</c>, which
    /// would otherwise emit <c>"System.Byte[]"</c> for the ciphertext.
    /// </summary>
    private bool PrintMembers(StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Append("ProviderId = ").Append(ProviderId);
        builder.Append(", KeyId = ").Append(KeyId);
        builder.Append(", Algorithm = ").Append(Algorithm);
        builder.Append(", Ciphertext = <").Append(Ciphertext.Length).Append(" bytes>");
        return true;
    }

    private static WrappedContentKey DecodeCore(string token)
    {
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
