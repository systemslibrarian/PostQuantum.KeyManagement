using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.KeyManagement.Local;

/// <summary>
/// A single derived local key-encryption key held in memory: its identifier, the 32-byte key
/// material, the salt it was derived from, and a non-secret verifier that lets a later process
/// detect a wrong passphrase at import time instead of at first unwrap.
/// </summary>
/// <remarks>
/// Zeroes its key material on disposal. The verifier is non-secret (it is a deterministic function
/// of the KEK) and is safe to persist alongside the salt.
/// </remarks>
internal sealed class LocalKek : IDisposable
{
    // A fixed, public domain-separation label. Keeping it constant across format versions means
    // the v3 verifier (full 32 bytes) is a prefix-extension of the v2 verifier (first 16 bytes of
    // the same HMAC-SHA256 output), so v2 keyrings keep importing correctly under the v3 reader.
    private static readonly byte[] VerifierLabel = Encoding.ASCII.GetBytes("PostQuantum.KeyManagement/v1/kek-verifier");

    /// <summary>Length of the per-KEK verifier, in bytes. Full HMAC-SHA256 output.</summary>
    public const int VerifierSizeInBytes = 32;

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
    /// A 32-byte HMAC-SHA256 tag over a fixed domain-separation label, keyed by this KEK. Non-secret;
    /// safe to persist. Used to detect a wrong passphrase at import time without ever holding any
    /// wrapped-key material. v2 keyring tokens stored the first 16 bytes of this value and are
    /// still accepted by the v3 reader via constant-time prefix comparison.
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

    // The verifier is non-secret — its purpose is to detect a wrong passphrase at import time —
    // so it does not need to be zeroed. Emit the full HMAC-SHA256 output to match the library's
    // 256-bit posture; v2 readers persisted the first 16 bytes of the same value.
    private static byte[] ComputeVerifier(byte[] key) => HMACSHA256.HashData(key, VerifierLabel);

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
