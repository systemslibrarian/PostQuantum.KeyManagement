using System.Security.Cryptography;

namespace PostQuantum.KeyManagement;

/// <summary>
/// A plaintext content key (data-encryption key) together with its persistable wrapped form.
/// </summary>
/// <remarks>
/// The plaintext key material in <see cref="Key"/> is sensitive. Dispose this instance as soon as
/// the key is no longer needed; <see cref="Dispose"/> zeroes the underlying buffer so it does not
/// linger in memory longer than necessary.
/// </remarks>
public sealed class ContentKey : IDisposable
{
    private readonly byte[] _key;
    private bool _disposed;

    internal ContentKey(byte[] key, WrappedContentKey wrappedKey)
    {
        _key = key;
        WrappedKey = wrappedKey;
    }

    /// <summary>
    /// The wrapped form of this content key. Safe to persist alongside ciphertext; required to
    /// recover the key later via <see cref="IContentKeyProvider.UnwrapAsync"/>.
    /// </summary>
    public WrappedContentKey WrappedKey { get; }

    /// <summary>The plaintext content key material. Sensitive — do not log or persist.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public ReadOnlySpan<byte> Key
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key;
        }
    }

    /// <summary>Zeroes the plaintext key material and marks the instance unusable.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_key);
        _disposed = true;
    }
}
