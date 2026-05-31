namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// Argon2id work-factor parameters used when deriving a local key-encryption key from a passphrase.
/// </summary>
/// <remarks>
/// The defaults follow the OWASP "interactive" guidance (64&#160;MiB memory, 3 iterations, parallelism 4)
/// and are a reasonable starting point for server-side use. Tune them upward for higher-value secrets
/// and benchmark on your target hardware. Whatever values you choose must be reproduced exactly when
/// re-deriving the same KEK, so persist them alongside the salt.
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
