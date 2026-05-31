using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// A single derived local key-encryption key held in memory: its identifier, the 32-byte key
/// material, the salt it was derived from, and a short non-secret verifier that lets a later
/// process detect a wrong passphrase at import time instead of at first unwrap.
/// </summary>
/// <remarks>
/// Zeroes its key material on disposal.
/// </remarks>
internal sealed class LocalKek : IDisposable
{
    // A fixed, public domain-separation label. Keeping it constant means the verifier is purely a
    // function of the derived KEK, so it can be recomputed in a future process from the passphrase
    // and salt and compared against the persisted value.
    private static readonly byte[] VerifierLabel = Encoding.ASCII.GetBytes("PostQuantum.KeyManagement/v1/kek-verifier");

    /// <summary>Length of the per-KEK verifier, in bytes. Truncated HMAC-SHA256.</summary>
    public const int VerifierSizeInBytes = 16;

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
        Verifier = ComputeVerifier(key);
    }

    internal string KeyId { get; }

    internal byte[] Salt { get; }

    internal int DegreeOfParallelism { get; }

    internal int MemorySizeInKib { get; }

    internal int Iterations { get; }

    /// <summary>
    /// A 16-byte HMAC-SHA256 tag over a fixed domain-separation label, keyed by this KEK. Non-secret;
    /// safe to persist. Used to detect a wrong passphrase at import time without ever holding any
    /// wrapped-key material.
    /// </summary>
    internal byte[] Verifier { get; }

    internal ReadOnlySpan<byte> Key
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key;
        }
    }

    private static byte[] ComputeVerifier(byte[] key)
    {
        byte[] full = HMACSHA256.HashData(key, VerifierLabel);
        try
        {
            byte[] tag = new byte[VerifierSizeInBytes];
            full.AsSpan(0, VerifierSizeInBytes).CopyTo(tag);
            return tag;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(full);
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
