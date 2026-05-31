namespace PostQuantum.KeyManagement;

/// <summary>
/// Provides envelope-encryption content keys (data-encryption keys, "DEKs") that are
/// wrapped by a key-encryption key ("KEK") owned and protected by the provider.
/// </summary>
/// <remarks>
/// <para>
/// The contract is intentionally small so that local and cloud-KMS implementations look
/// identical to callers:
/// </para>
/// <list type="bullet">
///   <item><description>Call <see cref="CreateContentKeyAsync"/> to mint a fresh content key. Use
///   <see cref="ContentKey.Key"/> to encrypt your data and persist
///   <see cref="ContentKey.WrappedKey"/> alongside the ciphertext.</description></item>
///   <item><description>Call <see cref="UnwrapAsync"/> with the stored
///   <see cref="WrappedContentKey"/> to recover the content key for decryption.</description></item>
///   <item><description>Call <see cref="RewrapAsync"/> during key rotation to re-wrap an existing
///   content key under the provider's current active KEK without changing the underlying data.</description></item>
/// </list>
/// </remarks>
public interface IContentKeyProvider
{
    /// <summary>
    /// A stable identifier for this provider family (for example, <c>"local"</c>). Persisted on
    /// every <see cref="WrappedContentKey"/> so the correct provider can be selected at unwrap time.
    /// </summary>
    string ProviderId { get; }

    /// <summary>
    /// The identifier of the key-encryption key currently used to wrap newly created content keys.
    /// Rotation changes this value while older KEKs remain available for unwrapping existing keys.
    /// </summary>
    string ActiveKeyId { get; }

    /// <summary>
    /// Generates a fresh random content key and wraps it under the active KEK.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// A <see cref="ContentKey"/> holding the plaintext key material (for immediate use) and the
    /// <see cref="WrappedContentKey"/> that must be persisted to recover it later. Dispose the
    /// result as soon as the plaintext key is no longer needed.
    /// </returns>
    ValueTask<ContentKey> CreateContentKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Unwraps a previously persisted <see cref="WrappedContentKey"/> back into usable key material.
    /// </summary>
    /// <param name="wrappedKey">The wrapped key produced by this provider family.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The recovered <see cref="ContentKey"/>. Dispose it when finished.</returns>
    ValueTask<ContentKey> UnwrapAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Re-wraps an existing content key under the provider's current active KEK. The underlying
    /// content key material is unchanged, so data encrypted with it remains decryptable; only the
    /// wrapping KEK changes. This is the core primitive for key rotation.
    /// </summary>
    /// <param name="wrappedKey">A wrapped key produced earlier by this provider family.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A new <see cref="WrappedContentKey"/> wrapped under <see cref="ActiveKeyId"/>.</returns>
    ValueTask<WrappedContentKey> RewrapAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken = default);
}
