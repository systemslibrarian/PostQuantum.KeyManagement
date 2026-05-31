using System.Security.Cryptography;

namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// A single derived local key-encryption key held in memory: its identifier, the 32-byte key
/// material, and the salt it was derived from. Zeroes its key material on disposal.
/// </summary>
internal sealed class LocalKek : IDisposable
{
    private readonly byte[] _key;
    private bool _disposed;

    internal LocalKek(string keyId, byte[] key, byte[] salt, int degreeOfParallelism, int memorySizeInKib, int iterations)
    {
        KeyId = keyId;
        _key = key;
        Salt = salt;
        DegreeOfParallelism = degreeOfParallelism;
        MemorySizeInKib = memorySizeInKib;
        Iterations = iterations;
    }

    internal string KeyId { get; }

    internal byte[] Salt { get; }

    internal int DegreeOfParallelism { get; }

    internal int MemorySizeInKib { get; }

    internal int Iterations { get; }

    internal ReadOnlySpan<byte> Key
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key;
        }
    }

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
