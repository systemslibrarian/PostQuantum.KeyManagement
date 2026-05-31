namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// The non-secret description of a single local key-encryption key: everything needed to re-derive it
/// from its passphrase, plus an optional integrity verifier that lets import detect a wrong
/// passphrase immediately. Contains no key material and no passphrase. Safe to persist.
/// </summary>
public sealed record LocalKekMetadata
{
    /// <summary>The KEK identifier (derived from <see cref="Salt"/>).</summary>
    public required string KeyId { get; init; }

    /// <summary>The Argon2id salt this KEK was derived with. Not a secret.</summary>
    public required byte[] Salt { get; init; }

    /// <summary>The Argon2id degree of parallelism used to derive this KEK.</summary>
    public required int DegreeOfParallelism { get; init; }

    /// <summary>The Argon2id memory cost, in kibibytes, used to derive this KEK.</summary>
    public required int MemorySizeInKib { get; init; }

    /// <summary>The Argon2id iteration count used to derive this KEK.</summary>
    public required int Iterations { get; init; }

    /// <summary>
    /// Optional 16-byte HMAC-SHA256 tag over a fixed library label, keyed by the KEK. If present,
    /// <see cref="LocalContentKeyProvider.Import(LocalKeyringMetadata,PassphraseResolver)"/> recomputes
    /// it during derivation and rejects the passphrase if the tags differ — failing fast with a
    /// clear error instead of a delayed <c>AuthenticationTagMismatchException</c> at first unwrap.
    /// </summary>
    /// <remarks>
    /// Non-secret. Absent on metadata produced by v0.2 (or earlier) of the library; present and
    /// checked on metadata produced by v0.3 and newer.
    /// </remarks>
    public byte[]? Verifier { get; init; }

    internal LocalKekOptions ToOptions() => new()
    {
        DegreeOfParallelism = DegreeOfParallelism,
        MemorySizeInKib = MemorySizeInKib,
        Iterations = Iterations,
    };
}
