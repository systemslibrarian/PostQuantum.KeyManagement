using System.Security.Cryptography;
using System.Text;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class RoundTripTests
{
    [Fact]
    public async Task CreateThenUnwrap_RecoversTheSameContentKey()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("correct horse battery staple", TestDefaults.FastKek);

        using ContentKey created = await provider.CreateContentKeyAsync();
        byte[] original = created.Key.ToArray();

        using ContentKey unwrapped = await provider.UnwrapAsync(created.WrappedKey);

        Assert.Equal(ContentKeyProvider.ContentKeySizeInBytes, original.Length);
        Assert.True(CryptographicOperations.FixedTimeEquals(original, unwrapped.Key));
    }

    [Fact]
    public async Task ContentKey_EncryptsAndDecryptsRealData_EndToEnd()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("a strong passphrase", TestDefaults.FastKek);
        byte[] plaintext = Encoding.UTF8.GetBytes("To God be the glory.");

        // Encrypt with a fresh content key; persist only the wrapped key.
        WrappedContentKey stored;
        byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
        using (ContentKey key = await provider.CreateContentKeyAsync())
        {
            using var aes = new AesGcm(key.Key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
            stored = key.WrappedKey;
        }

        // Later: recover the content key from the wrapped form and decrypt.
        byte[] decrypted = new byte[ciphertext.Length];
        using (ContentKey key = await provider.UnwrapAsync(stored))
        {
            using var aes = new AesGcm(key.Key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, decrypted);
        }

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task WrappedKey_EncodeDecode_RoundTripsAndStillUnwraps()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("token round trip", TestDefaults.FastKek);
        using ContentKey created = await provider.CreateContentKeyAsync();
        byte[] original = created.Key.ToArray();

        string token = created.WrappedKey.Encode();
        WrappedContentKey decoded = WrappedContentKey.Decode(token);

        Assert.Equal(created.WrappedKey.ProviderId, decoded.ProviderId);
        Assert.Equal(created.WrappedKey.KeyId, decoded.KeyId);
        Assert.Equal(created.WrappedKey.Algorithm, decoded.Algorithm);
        Assert.Equal(created.WrappedKey.Ciphertext, decoded.Ciphertext);

        using ContentKey unwrapped = await provider.UnwrapAsync(decoded);
        Assert.True(CryptographicOperations.FixedTimeEquals(original, unwrapped.Key));
    }

    [Fact]
    public async Task SameSaltAndPassphrase_ReproduceTheSameKekAcrossInstances()
    {
        WrappedContentKey stored;
        byte[] salt;
        byte[] original;

        using (LocalContentKeyProvider first = LocalContentKeyProvider.Create("persisted secret", TestDefaults.FastKek))
        {
            salt = first.ActiveSalt.ToArray();
            using ContentKey key = await first.CreateContentKeyAsync();
            stored = key.WrappedKey;
            original = key.Key.ToArray();
        }

        // A brand-new process re-derives the same KEK from the persisted salt + passphrase.
        using LocalContentKeyProvider second = LocalContentKeyProvider.Create("persisted secret", salt, TestDefaults.FastKek);
        using ContentKey recovered = await second.UnwrapAsync(stored);

        Assert.Equal(stored.KeyId, second.ActiveKeyId);
        Assert.True(CryptographicOperations.FixedTimeEquals(original, recovered.Key));
    }

    [Fact]
    public async Task UnwrapWithWrongPassphrase_Fails()
    {
        WrappedContentKey stored;
        byte[] salt;

        using (LocalContentKeyProvider right = LocalContentKeyProvider.Create("the real passphrase", TestDefaults.FastKek))
        {
            salt = right.ActiveSalt.ToArray();
            using ContentKey key = await right.CreateContentKeyAsync();
            stored = key.WrappedKey;
        }

        using LocalContentKeyProvider wrong = LocalContentKeyProvider.Create("a different passphrase", salt, TestDefaults.FastKek);

        // Same salt but different passphrase derives a different KEK with the same id, so the
        // authenticated decryption must fail rather than return garbage.
        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            async () => await wrong.UnwrapAsync(stored));
    }
}
