namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// Argon2id work-factor parameters used when deriving a local key-encryption key from a passphrase.
/// </summary>
/// <remarks>
/// <para>
/// The instance defaults match <see cref="Interactive"/> — RFC 9106's "second recommended" setting
/// (64&#160;MiB memory, 3 iterations, parallelism 4) — and are a reasonable starting point for
/// server-side use. For higher-value secrets prefer <see cref="Moderate"/> or <see cref="Sensitive"/>;
/// for low-end hardware where 64&#160;MiB is too costly, use <see cref="LowMemory"/>.
/// </para>
/// <para>
/// Whatever values you choose must be reproduced exactly when re-deriving the same KEK, so persist
/// them alongside the salt. The exported <see cref="LocalKeyringMetadata"/> already records them
/// per-KEK.
/// </para>
/// </remarks>
public sealed class LocalKekOptions
{
    /// <summary>Number of lanes / threads Argon2id uses. Default: 4.</summary>
    public int DegreeOfParallelism { get; init; } = 4;

    /// <summary>Memory cost in kibibytes. Default: 65536 (64&#160;MiB).</summary>
    public int MemorySizeInKib { get; init; } = 65536;

    /// <summary>Number of passes over memory (time cost). Default: 3.</summary>
    public int Iterations { get; init; } = 3;

    /// <summary>Length of the randomly generated salt, in bytes, when a salt is not supplied. Default: 16.</summary>
    public int SaltSizeInBytes { get; init; } = 16;

    /// <summary>
    /// RFC 9106 §4 "second recommended" option (and OWASP's interactive guidance): 64&#160;MiB memory,
    /// 3 iterations, parallelism 4. The instance defaults match this — a good starting point for
    /// server-side workloads where derivation latency must stay sub-second.
    /// </summary>
    public static LocalKekOptions Interactive { get; } = new();

    /// <summary>
    /// Stronger than <see cref="Interactive"/>: 256&#160;MiB memory, 4 iterations, parallelism 4. For
    /// secrets whose derivation can afford a few hundred milliseconds (background jobs, key import,
    /// administrative operations).
    /// </summary>
    public static LocalKekOptions Moderate { get; } = new()
    {
        DegreeOfParallelism = 4,
        MemorySizeInKib = 256 * 1024,
        Iterations = 4,
        SaltSizeInBytes = 16,
    };

    /// <summary>
    /// RFC 9106 §4 "first recommended" option: 2&#160;GiB memory, 1 iteration, parallelism 4. For
    /// long-lived high-value secrets (e.g. master KEKs) on hardware that can spare the RAM.
    /// </summary>
    public static LocalKekOptions Sensitive { get; } = new()
    {
        DegreeOfParallelism = 4,
        MemorySizeInKib = 2 * 1024 * 1024,
        Iterations = 1,
        SaltSizeInBytes = 16,
    };

    /// <summary>
    /// OWASP minimum for environments where 64&#160;MiB is unaffordable (CI, constrained devices):
    /// 19&#160;MiB memory, 2 iterations, parallelism 1. Use only when <see cref="Interactive"/> is
    /// genuinely out of reach.
    /// </summary>
    public static LocalKekOptions LowMemory { get; } = new()
    {
        DegreeOfParallelism = 1,
        MemorySizeInKib = 19 * 1024,
        Iterations = 2,
        SaltSizeInBytes = 16,
    };

    internal void Validate()
    {
        if (DegreeOfParallelism < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(DegreeOfParallelism), DegreeOfParallelism, "Must be at least 1.");
        }

        if (MemorySizeInKib < 8)
        {
            throw new ArgumentOutOfRangeException(nameof(MemorySizeInKib), MemorySizeInKib, "Must be at least 8 KiB.");
        }

        if (Iterations < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(Iterations), Iterations, "Must be at least 1.");
        }

        if (SaltSizeInBytes < 8)
        {
            throw new ArgumentOutOfRangeException(nameof(SaltSizeInBytes), SaltSizeInBytes, "Must be at least 8 bytes.");
        }
    }
}
