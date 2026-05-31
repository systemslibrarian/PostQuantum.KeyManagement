using PostQuantum.KeyManagement.Local;

namespace PostQuantum.KeyManagement.Extensions.DependencyInjection;

/// <summary>
/// Persists and retrieves the non-secret <see cref="LocalKeyringMetadata"/> blob used to rebuild a
/// <see cref="LocalContentKeyProvider"/> after a process restart.
/// </summary>
/// <remarks>
/// <para>
/// Implementations decide where the blob lives: a file on disk (<see cref="FileKeyringStore"/>), a
/// configuration provider, an external secret manager, an object store, etc. The blob produced by
/// <see cref="LocalKeyringMetadata.Encode"/> is non-secret — it does not contain key material or
/// passphrases — so storage need only be durable, not strongly protected.
/// </para>
/// <para>
/// Implementations must be safe to call from background services. <see cref="SaveAsync"/> should be
/// atomic with respect to readers — partial writes that another process could observe are a
/// correctness bug.
/// </para>
/// </remarks>
public interface IKeyringStore
{
    /// <summary>
    /// Loads the previously persisted keyring blob. Returns <see langword="null"/> when no blob is
    /// present (first run).
    /// </summary>
    ValueTask<string?> LoadAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically persists the given keyring blob. Implementations must not leave a partial file
    /// or partial record visible to readers if the operation fails or the host is killed.
    /// </summary>
    ValueTask SaveAsync(string token, CancellationToken cancellationToken = default);
}
