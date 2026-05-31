using System.Text;

namespace PostQuantum.KeyManagement.Extensions.DependencyInjection;

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
        if (!File.Exists(_path))
        {
            return null;
        }

#if NET8_0_OR_GREATER
        return await File.ReadAllTextAsync(_path, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
#else
        return await File.ReadAllTextAsync(_path, Encoding.UTF8).ConfigureAwait(false);
#endif
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

            // File.Replace is atomic on Windows and on POSIX filesystems that support rename(2).
            // When the destination doesn't exist yet, fall back to Move (also atomic on the same volume).
            if (File.Exists(_path))
            {
                File.Replace(tempPath, _path, destinationBackupFileName: null);
            }
            else
            {
                File.Move(tempPath, _path);
            }
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
}
