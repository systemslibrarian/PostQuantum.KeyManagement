using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// A self-contained <see cref="IContentKeyProvider"/> whose key-encryption keys are derived from
/// passphrases using Argon2id and which wraps content keys with AES-256-GCM. No external service is
/// required, which makes it ideal for local files, tests, and air-gapped scenarios, and a faithful
/// reference for how cloud-KMS providers should behave.
/// </summary>
/// <remarks>
/// <para>
/// The provider holds a small in-memory key ring. The <see cref="ActiveKeyId"/> KEK wraps new content
/// keys; rotating in a new KEK (see <see cref="Rotate(System.ReadOnlySpan{char},LocalKekOptions?)"/>)
/// keeps the previous KEKs available so existing wrapped keys still unwrap, and
/// <see cref="ContentKeyProvider.RewrapAsync"/> can migrate them to the new KEK over time.
/// </para>
/// <para>
/// <b>Persistence is the caller's responsibility.</b> To re-derive a KEK in a later process you must
/// store its <see cref="ActiveSalt"/> (and any non-default <see cref="LocalKekOptions"/>) and supply
/// the same passphrase. The salt is not a secret; the passphrase is. See KNOWN-GAPS.md.
/// </para>
/// </remarks>
public sealed class LocalContentKeyProvider : ContentKeyProvider, IDisposable
{
    /// <summary>The <see cref="ContentKeyProvider.ProviderId"/> value for this provider family.</summary>
    public const string Provider = "local";

    private const int NonceSizeInBytes = 12;
    private const int TagSizeInBytes = 16;

    private readonly Dictionary<string, LocalKek> _keyRing;
    private string _activeKeyId;
    private bool _disposed;

    private LocalContentKeyProvider(LocalKek active)
        : this(new Dictionary<string, LocalKek>(StringComparer.Ordinal) { [active.KeyId] = active }, active.KeyId)
    {
    }

    private LocalContentKeyProvider(Dictionary<string, LocalKek> keyRing, string activeKeyId)
    {
        _keyRing = keyRing;
        _activeKeyId = activeKeyId;
    }

    /// <inheritdoc />
    public override string ProviderId => Provider;

    /// <inheritdoc />
    public override string ActiveKeyId
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _activeKeyId;
        }
    }

    /// <inheritdoc />
    protected override string WrapAlgorithm => "AES-256-GCM";

    /// <summary>The salt used to derive the current active KEK. Persist it to re-derive that KEK later.</summary>
    public ReadOnlyMemory<byte> ActiveSalt
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _keyRing[_activeKeyId].Salt;
        }
    }

    /// <summary>
    /// Creates a provider with a single active KEK derived from <paramref name="passphrase"/> and a
    /// freshly generated random salt. Read <see cref="ActiveSalt"/> afterwards if you need to persist it.
    /// </summary>
    public static LocalContentKeyProvider Create(ReadOnlySpan<char> passphrase, LocalKekOptions? options = null)
    {
        options ??= new LocalKekOptions();
        options.Validate();
        byte[] salt = RandomNumberGenerator.GetBytes(options.SaltSizeInBytes);
        return new LocalContentKeyProvider(DeriveKek(passphrase, salt, options));
    }

    /// <summary>
    /// Re-creates a provider whose active KEK is derived from <paramref name="passphrase"/> and a
    /// previously persisted <paramref name="salt"/>. The same passphrase, salt, and options reproduce
    /// the identical KEK (and <see cref="ActiveKeyId"/>), so existing wrapped keys unwrap correctly.
    /// </summary>
    public static LocalContentKeyProvider Create(ReadOnlySpan<char> passphrase, ReadOnlySpan<byte> salt, LocalKekOptions? options = null)
    {
        options ??= new LocalKekOptions();
        options.Validate();
        return new LocalContentKeyProvider(DeriveKek(passphrase, salt.ToArray(), options));
    }

    /// <summary>
    /// Derives a new KEK from <paramref name="newPassphrase"/> and a fresh random salt, adds it to the
    /// key ring, and makes it the active KEK. Previous KEKs remain available for unwrapping.
    /// </summary>
    /// <returns>The identifier of the new active KEK.</returns>
    public string Rotate(ReadOnlySpan<char> newPassphrase, LocalKekOptions? options = null)
    {
        options ??= new LocalKekOptions();
        options.Validate();
        byte[] salt = RandomNumberGenerator.GetBytes(options.SaltSizeInBytes);
        return Rotate(newPassphrase, salt, options);
    }

    /// <summary>
    /// Derives a new KEK from <paramref name="newPassphrase"/> and the supplied <paramref name="salt"/>,
    /// adds it to the key ring, and makes it the active KEK. Previous KEKs remain available for unwrapping.
    /// </summary>
    /// <returns>The identifier of the new active KEK.</returns>
    public string Rotate(ReadOnlySpan<char> newPassphrase, ReadOnlySpan<byte> salt, LocalKekOptions? options = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        options ??= new LocalKekOptions();
        options.Validate();

        LocalKek kek = DeriveKek(newPassphrase, salt.ToArray(), options);
        if (_keyRing.TryGetValue(kek.KeyId, out LocalKek? existing) && !ReferenceEquals(existing, kek))
        {
            existing.Dispose();
        }

        _keyRing[kek.KeyId] = kek;
        _activeKeyId = kek.KeyId;
        return kek.KeyId;
    }

    /// <summary>
    /// Exports the non-secret structure of the entire key ring — every KEK's salt and Argon2id cost
    /// parameters plus the active KEK id. Persist the result (optionally via
    /// <see cref="LocalKeyringMetadata.Encode"/>) and pair it with the passphrases at import time to
    /// reconstruct this provider in a later process. The export contains no key material or passphrases.
    /// </summary>
    public LocalKeyringMetadata ExportMetadata()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        List<LocalKekMetadata> keks = _keyRing.Values
            .OrderBy(kek => kek.KeyId, StringComparer.Ordinal)
            .Select(kek => new LocalKekMetadata
            {
                KeyId = kek.KeyId,
                Salt = kek.Salt.ToArray(),
                DegreeOfParallelism = kek.DegreeOfParallelism,
                MemorySizeInKib = kek.MemorySizeInKib,
                Iterations = kek.Iterations,
            })
            .ToList();

        return new LocalKeyringMetadata { ActiveKeyId = _activeKeyId, Keks = keks };
    }

    /// <summary>
    /// Reconstructs a provider from previously exported <see cref="LocalKeyringMetadata"/>, re-deriving
    /// each KEK from its salt/parameters and the passphrase returned by <paramref name="passphraseResolver"/>.
    /// </summary>
    /// <param name="metadata">Keyring metadata produced by <see cref="ExportMetadata"/>.</param>
    /// <param name="passphraseResolver">Supplies the passphrase for each KEK, keyed by its id.</param>
    /// <exception cref="ArgumentException">The metadata contains no KEKs.</exception>
    /// <exception cref="InvalidOperationException">A salt is corrupt, or the active KEK is absent from the ring.</exception>
    public static LocalContentKeyProvider Import(LocalKeyringMetadata metadata, PassphraseResolver passphraseResolver)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(passphraseResolver);
        if (metadata.Keks.Count == 0)
        {
            throw new ArgumentException("Keyring metadata contains no KEKs to import.", nameof(metadata));
        }

        var keyRing = new Dictionary<string, LocalKek>(StringComparer.Ordinal);
        try
        {
            foreach (LocalKekMetadata kekMetadata in metadata.Keks)
            {
                ArgumentNullException.ThrowIfNull(kekMetadata);
                LocalKekOptions options = kekMetadata.ToOptions();
                options.Validate();

                LocalKek kek = DeriveKek(passphraseResolver(kekMetadata.KeyId), kekMetadata.Salt.ToArray(), options);

                // The key id is a function of the salt, so a mismatch means the metadata's salt and id
                // disagree — i.e. the metadata is corrupt. (Passphrase correctness is verified later, at
                // unwrap time, by AES-GCM authentication.)
                if (!string.Equals(kek.KeyId, kekMetadata.KeyId, StringComparison.Ordinal))
                {
                    kek.Dispose();
                    throw new InvalidOperationException(
                        $"Re-derived key id '{kek.KeyId}' does not match metadata key id '{kekMetadata.KeyId}'; the salt is corrupt.");
                }

                if (keyRing.TryGetValue(kek.KeyId, out LocalKek? duplicate))
                {
                    duplicate.Dispose();
                }

                keyRing[kek.KeyId] = kek;
            }

            if (!keyRing.ContainsKey(metadata.ActiveKeyId))
            {
                throw new InvalidOperationException(
                    $"Active key id '{metadata.ActiveKeyId}' is not present in the imported keyring.");
            }

            return new LocalContentKeyProvider(keyRing, metadata.ActiveKeyId);
        }
        catch
        {
            foreach (LocalKek kek in keyRing.Values)
            {
                kek.Dispose();
            }

            throw;
        }
    }

    /// <inheritdoc />
    protected override ValueTask<byte[]> WrapKeyAsync(string keyId, ReadOnlyMemory<byte> contentKey, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        LocalKek kek = GetKek(keyId);

        // Layout: nonce (12) || tag (16) || ciphertext (== contentKey length).
        byte[] blob = new byte[NonceSizeInBytes + TagSizeInBytes + contentKey.Length];
        Span<byte> nonce = blob.AsSpan(0, NonceSizeInBytes);
        Span<byte> tag = blob.AsSpan(NonceSizeInBytes, TagSizeInBytes);
        Span<byte> ciphertext = blob.AsSpan(NonceSizeInBytes + TagSizeInBytes);

        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(kek.Key, TagSizeInBytes);
        aes.Encrypt(nonce, contentKey.Span, ciphertext, tag);

        return new ValueTask<byte[]>(blob);
    }

    /// <inheritdoc />
    protected override ValueTask<byte[]> UnwrapKeyAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        LocalKek kek = GetKek(wrappedKey.KeyId);
        byte[] blob = wrappedKey.Ciphertext;
        if (blob.Length < NonceSizeInBytes + TagSizeInBytes)
        {
            throw new CryptographicException("Wrapped key blob is too short to be valid.");
        }

        ReadOnlySpan<byte> nonce = blob.AsSpan(0, NonceSizeInBytes);
        ReadOnlySpan<byte> tag = blob.AsSpan(NonceSizeInBytes, TagSizeInBytes);
        ReadOnlySpan<byte> ciphertext = blob.AsSpan(NonceSizeInBytes + TagSizeInBytes);

        byte[] plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(kek.Key, TagSizeInBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }

        return new ValueTask<byte[]>(plaintext);
    }

    private LocalKek GetKek(string keyId)
    {
        if (!_keyRing.TryGetValue(keyId, out LocalKek? kek))
        {
            throw new KeyNotFoundException(
                $"No local KEK with id '{keyId}' is loaded. Re-create the provider with the passphrase and salt used to derive it.");
        }

        return kek;
    }

    private static LocalKek DeriveKek(ReadOnlySpan<char> passphrase, byte[] salt, LocalKekOptions options)
    {
        // Convert the passphrase to an exact-length byte array we can zero after derivation.
        int byteCount = Encoding.UTF8.GetByteCount(passphrase);
        byte[] password = new byte[byteCount];
        Encoding.UTF8.GetBytes(passphrase, password);

        try
        {
            using var argon2 = new Argon2id(password)
            {
                Salt = salt,
                DegreeOfParallelism = options.DegreeOfParallelism,
                MemorySize = options.MemorySizeInKib,
                Iterations = options.Iterations,
            };

            byte[] key = argon2.GetBytes(ContentKeySizeInBytes);
            return new LocalKek(ComputeKeyId(salt), key, salt, options.DegreeOfParallelism, options.MemorySizeInKib, options.Iterations);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    private static string ComputeKeyId(byte[] salt)
    {
        // A stable, non-secret label derived from the salt: same salt -> same key id.
        byte[] hash = SHA256.HashData(salt);
        return "local-" + Convert.ToHexString(hash, 0, 6).ToLowerInvariant();
    }

    /// <summary>Zeroes and releases every KEK held in the key ring.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        foreach (LocalKek kek in _keyRing.Values)
        {
            kek.Dispose();
        }

        _keyRing.Clear();
        _disposed = true;
    }
}
