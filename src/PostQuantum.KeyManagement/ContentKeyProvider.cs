using System.Security.Cryptography;

namespace PostQuantum.KeyManagement;

/// <summary>
/// Base class for <see cref="IContentKeyProvider"/> implementations. It owns the envelope-encryption
/// workflow — generating random content keys, packaging <see cref="WrappedContentKey"/> values, and
/// driving rotation — and leaves only the provider-specific wrap/unwrap of the key material to
/// derived types.
/// </summary>
/// <remarks>
/// This is the primary extensibility point for new providers. A cloud KMS provider (Azure Key Vault,
/// AWS KMS, Google Cloud KMS, an HSM, …) needs to override only <see cref="WrapKeyAsync"/> and
/// <see cref="UnwrapKeyAsync"/>, delegating those calls to the remote service, and expose its
/// <see cref="ProviderId"/>, <see cref="ActiveKeyId"/>, and <see cref="WrapAlgorithm"/>.
/// </remarks>
public abstract class ContentKeyProvider : IContentKeyProvider
{
    /// <summary>The length, in bytes, of the content keys this base class generates (256-bit).</summary>
    public const int ContentKeySizeInBytes = 32;

    /// <inheritdoc />
    public abstract string ProviderId { get; }

    /// <inheritdoc />
    public abstract string ActiveKeyId { get; }

    /// <summary>The algorithm label recorded on wrapped keys (for example, <c>"AES-256-GCM"</c>).</summary>
    protected abstract string WrapAlgorithm { get; }

    /// <summary>
    /// Wraps (encrypts) raw content-key material under the key-encryption key identified by
    /// <paramref name="keyId"/>, returning an opaque blob that <see cref="UnwrapKeyAsync"/> can reverse.
    /// </summary>
    protected abstract ValueTask<byte[]> WrapKeyAsync(string keyId, ReadOnlyMemory<byte> contentKey, CancellationToken cancellationToken);

    /// <summary>
    /// Unwraps (decrypts) the blob carried by <paramref name="wrappedKey"/> back into raw content-key
    /// material. Implementations should throw if the wrapped key references an unknown KEK.
    /// </summary>
    protected abstract ValueTask<byte[]> UnwrapKeyAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken);

    /// <inheritdoc />
    public async ValueTask<ContentKey> CreateContentKeyAsync(CancellationToken cancellationToken = default)
    {
        byte[] dek = RandomNumberGenerator.GetBytes(ContentKeySizeInBytes);
        try
        {
            string keyId = ActiveKeyId;
            byte[] ciphertext = await WrapKeyAsync(keyId, dek, cancellationToken).ConfigureAwait(false);
            var wrapped = new WrappedContentKey
            {
                ProviderId = ProviderId,
                KeyId = keyId,
                Algorithm = WrapAlgorithm,
                Ciphertext = ciphertext,
            };
            return new ContentKey(dek, wrapped);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(dek);
            throw;
        }
    }

    /// <inheritdoc />
    public async ValueTask<ContentKey> UnwrapAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        EnsureOwnedByThisProvider(wrappedKey);

        byte[] dek = await UnwrapKeyAsync(wrappedKey, cancellationToken).ConfigureAwait(false);
        return new ContentKey(dek, wrappedKey);
    }

    /// <inheritdoc />
    public async ValueTask<WrappedContentKey> RewrapAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        EnsureOwnedByThisProvider(wrappedKey);

        using ContentKey current = await UnwrapAsync(wrappedKey, cancellationToken).ConfigureAwait(false);

        // The wrap/unwrap contract is async, so the key material must briefly live in a heap array.
        // Zero it the moment the re-wrap completes.
        byte[] dekCopy = current.Key.ToArray();
        try
        {
            string keyId = ActiveKeyId;
            byte[] ciphertext = await WrapKeyAsync(keyId, dekCopy, cancellationToken).ConfigureAwait(false);
            return new WrappedContentKey
            {
                ProviderId = ProviderId,
                KeyId = keyId,
                Algorithm = WrapAlgorithm,
                Ciphertext = ciphertext,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dekCopy);
        }
    }

    /// <summary>
    /// Throws if <paramref name="wrappedKey"/> was produced by a different provider family. Call this
    /// before attempting to unwrap to fail fast with a clear message instead of a cryptographic error.
    /// </summary>
    protected void EnsureOwnedByThisProvider(WrappedContentKey wrappedKey)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        if (!string.Equals(wrappedKey.ProviderId, ProviderId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Wrapped key was produced by provider '{wrappedKey.ProviderId}', but this provider is '{ProviderId}'.");
        }
    }
}
