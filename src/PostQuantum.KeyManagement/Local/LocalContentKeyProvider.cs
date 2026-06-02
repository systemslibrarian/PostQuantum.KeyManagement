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
/// <b>Persistence:</b> the in-memory key ring can be exported via <see cref="ExportMetadata"/>
/// as a non-secret <see cref="LocalKeyringMetadata"/> and reconstructed in a later process with
/// <see cref="Import"/>. The export carries each KEK's salt, Argon2id parameters, and a 32-byte
/// HMAC-SHA256 verifier (v3 tokens; v2 tokens persisted the first 16 bytes of the same value and
/// continue to import correctly via a constant-time prefix comparison). The verifier lets
/// <see cref="Import"/> detect a wrong passphrase immediately instead of as a delayed
/// <see cref="AuthenticationTagMismatchException"/> at first unwrap.
/// </para>
/// <para>
/// <b>Thread-safety:</b> all members are safe to invoke concurrently from multiple threads.
/// Wrap/unwrap operations and <see cref="Rotate(System.ReadOnlySpan{char},LocalKekOptions?)"/>
/// serialise on a private lock so a rotation cannot dispose a KEK that another thread is using.
/// Calls do not block on cancellation tokens or on user code.
/// </para>
/// </remarks>
public sealed class LocalContentKeyProvider : ContentKeyProvider, IDisposable
{
    /// <summary>The <see cref="ContentKeyProvider.ProviderId"/> value for this provider family.</summary>
    public const string Provider = "local";

    private const int NonceSizeInBytes = 12;
    private const int TagSizeInBytes = 16;

    private readonly Dictionary<string, LocalKek> _keyRing;
    private readonly object _sync = new();
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
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _activeKeyId;
            }
        }
    }

    /// <inheritdoc />
    protected override string WrapAlgorithm => "AES-256-GCM";

    /// <summary>The salt used to derive the current active KEK. Persist it to re-derive that KEK later.</summary>
    public ReadOnlyMemory<byte> ActiveSalt
    {
        get
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _keyRing[_activeKeyId].Salt;
            }
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
    /// <exception cref="InvalidOperationException">
    /// The derived key id collides with an existing KEK in the ring. This signals that the supplied
    /// salt was already in use (almost always a caller bug — salts are meant to be unique per KEK);
    /// silently replacing the existing KEK would lose the ability to unwrap keys made under it.
    /// </exception>
    public string Rotate(ReadOnlySpan<char> newPassphrase, ReadOnlySpan<byte> salt, LocalKekOptions? options = null)
    {
        options ??= new LocalKekOptions();
        options.Validate();

        LocalKek kek = DeriveKek(newPassphrase, salt.ToArray(), options);
        try
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (_keyRing.ContainsKey(kek.KeyId))
                {
                    throw new InvalidOperationException(
                        $"A KEK with id '{kek.KeyId}' is already present in the keyring; refusing to rotate over it. " +
                        "Use a fresh salt (the default overload generates one for you).");
                }

                _keyRing[kek.KeyId] = kek;
                _activeKeyId = kek.KeyId;
                kek = null!; // ownership transferred
                return _activeKeyId;
            }
        }
        finally
        {
            kek?.Dispose();
        }
    }

    /// <summary>
    /// Exports the non-secret structure of the entire key ring — every KEK's salt, Argon2id cost
    /// parameters, and a 32-byte HMAC-SHA256 verifier, plus the active KEK id. Persist the result
    /// (optionally via <see cref="LocalKeyringMetadata.Encode"/>) and pair it with the passphrases at
    /// import time to reconstruct this provider in a later process. The export contains no key
    /// material or passphrases.
    /// </summary>
    public LocalKeyringMetadata ExportMetadata()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            List<LocalKekMetadata> keks = _keyRing.Values
                .OrderBy(kek => kek.KeyId, StringComparer.Ordinal)
                .Select(kek => new LocalKekMetadata
                {
                    KeyId = kek.KeyId,
                    Salt = kek.Salt.AsSpan().ToArray(),
                    DegreeOfParallelism = kek.DegreeOfParallelism,
                    MemorySizeInKib = kek.MemorySizeInKib,
                    Iterations = kek.Iterations,
                    Verifier = kek.Verifier.AsSpan().ToArray(),
                })
                .ToList();

            return new LocalKeyringMetadata { ActiveKeyId = _activeKeyId, Keks = keks };
        }
    }

    /// <summary>
    /// Reconstructs a provider from previously exported <see cref="LocalKeyringMetadata"/>, re-deriving
    /// each KEK from its salt/parameters and the passphrase returned by <paramref name="passphraseResolver"/>.
    /// </summary>
    /// <param name="metadata">Keyring metadata produced by <see cref="ExportMetadata"/>.</param>
    /// <param name="passphraseResolver">Supplies the passphrase for each KEK, keyed by its id.</param>
    /// <exception cref="ArgumentException">The metadata contains no KEKs.</exception>
    /// <exception cref="InvalidOperationException">
    /// A salt is corrupt, the active KEK is absent from the ring, or — when the metadata carries a
    /// verifier — the resolved passphrase does not match the one used at export. The verifier check
    /// is constant-time.
    /// </exception>
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

                LocalKek kek = DeriveKek(passphraseResolver(kekMetadata.KeyId), kekMetadata.Salt.AsSpan().ToArray(), options);

                // The key id is a function of the salt, so a mismatch means the metadata's salt and id
                // disagree — i.e. the metadata is corrupt.
                if (!string.Equals(kek.KeyId, kekMetadata.KeyId, StringComparison.Ordinal))
                {
                    kek.Dispose();
                    throw new InvalidOperationException(
                        $"Re-derived key id '{kek.KeyId}' does not match metadata key id '{kekMetadata.KeyId}'; the salt is corrupt.");
                }

                // If a verifier was persisted (v2 / v3 tokens), compare it in constant time. v3
                // stores the full 32-byte HMAC-SHA256; v2 stores the first 16 bytes of the same
                // value. Compare whatever width the token carries against the matching prefix of
                // the recomputed 32-byte verifier — the comparison is constant-time and accepts
                // both widths without weakening the v3 check. A mismatch means the resolved
                // passphrase is wrong; fail fast with a clear message instead of surfacing it
                // later as an AuthenticationTagMismatchException at first unwrap.
                if (kekMetadata.Verifier is { Length: > 0 } expected)
                {
                    if (expected.Length > kek.Verifier.Length
                        || !CryptographicOperations.FixedTimeEquals(expected, kek.Verifier.AsSpan(0, expected.Length)))
                    {
                        kek.Dispose();
                        throw new InvalidOperationException(
                            $"Verifier mismatch for KEK '{kekMetadata.KeyId}': the supplied passphrase does not match the one used at export.");
                    }
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
        cancellationToken.ThrowIfCancellationRequested();

        // Layout: nonce (12) || tag (16) || ciphertext (== contentKey length).
        byte[] blob = new byte[NonceSizeInBytes + TagSizeInBytes + contentKey.Length];
        Span<byte> nonce = blob.AsSpan(0, NonceSizeInBytes);
        Span<byte> tag = blob.AsSpan(NonceSizeInBytes, TagSizeInBytes);
        Span<byte> ciphertext = blob.AsSpan(NonceSizeInBytes + TagSizeInBytes);

        RandomNumberGenerator.Fill(nonce);

        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            LocalKek kek = GetKek(keyId);
            using var aes = new AesGcm(kek.Key, TagSizeInBytes);
            aes.Encrypt(nonce, contentKey.Span, ciphertext, tag);
        }

        return new ValueTask<byte[]>(blob);
    }

    /// <inheritdoc />
    protected override ValueTask<byte[]> UnwrapKeyAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        byte[] blob = wrappedKey.Ciphertext;
        if (blob.Length < NonceSizeInBytes + TagSizeInBytes)
        {
            throw new CryptographicException("Wrapped key blob is too short to be valid.");
        }

        int plaintextLength = blob.Length - NonceSizeInBytes - TagSizeInBytes;

        // The base class always wraps 32-byte DEKs. A blob whose payload is a different length is
        // either corrupt or produced by a foreign system; refusing it here makes the failure mode
        // clear ("malformed blob") rather than surfacing as a downstream caller bug.
        if (plaintextLength != ContentKeySizeInBytes)
        {
            throw new CryptographicException(
                $"Wrapped key payload is {plaintextLength} bytes; expected {ContentKeySizeInBytes}.");
        }

        ReadOnlySpan<byte> nonce = blob.AsSpan(0, NonceSizeInBytes);
        ReadOnlySpan<byte> tag = blob.AsSpan(NonceSizeInBytes, TagSizeInBytes);
        ReadOnlySpan<byte> ciphertext = blob.AsSpan(NonceSizeInBytes + TagSizeInBytes);

        byte[] plaintext = new byte[plaintextLength];
        try
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                LocalKek kek = GetKek(wrappedKey.KeyId);
                using var aes = new AesGcm(kek.Key, TagSizeInBytes);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
            }
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
        if (passphrase.IsEmpty)
        {
            throw new ArgumentException(
                "Passphrase must not be empty. An empty passphrase offers no entropy and is refused " +
                "by the Argon2id derivation; this check makes the failure mode explicit.",
                nameof(passphrase));
        }

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
        lock (_sync)
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
}
