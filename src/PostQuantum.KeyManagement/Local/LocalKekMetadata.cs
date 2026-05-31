using System.Text;

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

    /// <summary>
    /// Renders a diagnostic-friendly representation: identifiers and Argon2id parameters in full,
    /// byte arrays as <c>&lt;NN bytes&gt;</c>. Safe to log. Overrides the record's default
    /// <c>PrintMembers</c>, which would otherwise emit <c>"System.Byte[]"</c> for the salt and verifier.
    /// </summary>
    private bool PrintMembers(StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Append("KeyId = ").Append(KeyId);
        builder.Append(", Salt = <").Append(Salt.Length).Append(" bytes>");
        builder.Append(", DegreeOfParallelism = ").Append(DegreeOfParallelism);
        builder.Append(", MemorySizeInKib = ").Append(MemorySizeInKib);
        builder.Append(", Iterations = ").Append(Iterations);
        builder.Append(", Verifier = ");
        if (Verifier is null)
        {
            builder.Append("null");
        }
        else
        {
            builder.Append('<').Append(Verifier.Length).Append(" bytes>");
        }

        return true;
    }
}
