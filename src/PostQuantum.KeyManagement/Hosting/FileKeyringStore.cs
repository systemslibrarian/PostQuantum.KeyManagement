using System.Text;

namespace PostQuantum.KeyManagement;

/// <summary>
/// A file-backed <see cref="IKeyringStore"/> that persists the keyring blob to a single file and
/// writes atomically through a temporary sibling + rename, so a crash mid-write cannot leave the
/// target file in a half-written state that would fail to decode on the next start.
/// </summary>
public sealed class FileKeyringStore : IKeyringStore
{
    private readonly string _path;

    /// <summary>Creates a store rooted at <paramref name="path"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="path"/> is null or whitespace.</exception>
    public FileKeyringStore(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Keyring path must be a non-empty file path.", nameof(path));
        }

        _path = path;
    }

    /// <summary>The absolute or relative path the store is reading from / writing to.</summary>
    public string Path => _path;

    /// <inheritdoc />
    public async ValueTask<string?> LoadAsync(CancellationToken cancellationToken = default)
    {
        // Open with FileShare.ReadWrite | FileShare.Delete so a concurrent writer's atomic Replace
        // can swap underneath us; POSIX rename(2) doesn't care about open file descriptors either
        // way. On Windows, File.Replace leaves a brief window where the destination can transiently
        // appear missing — we retry FileNotFoundException a bounded number of times to ride
        // through that gap. If the file genuinely doesn't exist (first startup before a write),
        // every retry sees the same absence and we eventually return null.
        const int maxAttempts = 8;
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                await using var stream = new FileStream(
                    _path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete,
                    bufferSize: 4096,
                    useAsync: true);
                using var reader = new StreamReader(stream, Encoding.UTF8);
                return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (FileNotFoundException) when (attempt < maxAttempts)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(5 * attempt), cancellationToken).ConfigureAwait(false);
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                // Parent directory doesn't exist — the file definitively cannot.
                return null;
            }
            catch (IOException) when (attempt < maxAttempts)
            {
                // Windows can transiently report the destination as "in use" while a writer is
                // mid-Replace. Briefly back off and retry; POSIX never lands here.
                await Task.Delay(TimeSpan.FromMilliseconds(5 * attempt), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <inheritdoc />
    public async ValueTask SaveAsync(string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        string? directory = System.IO.Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        string tempPath = _path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(tempPath, token, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            await SwapInAtomicallyAsync(tempPath, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch
            {
                // Best-effort cleanup; let the original exception propagate.
            }

            throw;
        }
    }

    /// <summary>
    /// Renames <paramref name="tempPath"/> over <see cref="_path"/> atomically. On POSIX this is a
    /// single <c>rename(2)</c>. On Windows, <see cref="File.Replace(string, string, string?)"/> can
    /// throw <see cref="IOException"/> if a reader currently holds the destination open — this
    /// helper retries with a brief backoff so a single-writer + many-readers workload (the
    /// production deployment shape documented in docs/deployment.md) is not racy.
    /// </summary>
    private async ValueTask SwapInAtomicallyAsync(string tempPath, CancellationToken cancellationToken)
    {
        const int maxAttempts = 8;
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                // Fast path: destination already exists.
                File.Replace(tempPath, _path, destinationBackupFileName: null);
                return;
            }
            catch (FileNotFoundException)
            {
                // First-write path: destination does not exist yet. Try to materialise it via Move.
                try
                {
                    File.Move(tempPath, _path);
                    return;
                }
                catch (IOException) when (attempt < maxAttempts)
                {
                    // TOCTOU: another writer created the file between our Replace and our Move.
                    // Loop back and try Replace; if Move-vs-Replace races repeat, fall through to
                    // the IOException retry below.
                }
            }
            catch (IOException) when (attempt < maxAttempts)
            {
                // Windows: a reader may hold the destination open, blocking Replace. Brief backoff
                // and try again. POSIX never lands here.
            }

            await Task.Delay(TimeSpan.FromMilliseconds(5 * attempt), cancellationToken).ConfigureAwait(false);
        }
    }
}
