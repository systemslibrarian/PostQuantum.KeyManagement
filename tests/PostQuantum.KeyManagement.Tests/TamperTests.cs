using System.Security.Cryptography;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class TamperTests
{
    [Fact]
    public async Task BitFlipInCiphertext_FailsAuthentication_DoesNotReturnGarbage()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("a passphrase", TestDefaults.FastKek);
        using ContentKey created = await provider.CreateContentKeyAsync();

        byte[] tampered = (byte[])created.WrappedKey.Ciphertext.Clone();
        tampered[^1] ^= 0x01;

        var corrupt = new WrappedContentKey
        {
            ProviderId = created.WrappedKey.ProviderId,
            KeyId = created.WrappedKey.KeyId,
            Algorithm = created.WrappedKey.Algorithm,
            Ciphertext = tampered,
        };

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            async () => await provider.UnwrapAsync(corrupt));
    }

    [Fact]
    public async Task BitFlipInTag_FailsAuthentication()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("a passphrase", TestDefaults.FastKek);
        using ContentKey created = await provider.CreateContentKeyAsync();

        byte[] tampered = (byte[])created.WrappedKey.Ciphertext.Clone();
        // Tag bytes are immediately after the 12-byte nonce.
        tampered[12] ^= 0x80;

        var corrupt = new WrappedContentKey
        {
            ProviderId = created.WrappedKey.ProviderId,
            KeyId = created.WrappedKey.KeyId,
            Algorithm = created.WrappedKey.Algorithm,
            Ciphertext = tampered,
        };

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            async () => await provider.UnwrapAsync(corrupt));
    }

    [Fact]
    public async Task TruncatedBlob_FailsClearly_NotInsideTheCipher()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("a passphrase", TestDefaults.FastKek);
        using ContentKey created = await provider.CreateContentKeyAsync();

        // 12 + 16 = 28 bytes is the minimum for nonce+tag. Anything below is structurally invalid.
        byte[] truncated = created.WrappedKey.Ciphertext.AsSpan(0, 20).ToArray();
        var corrupt = new WrappedContentKey
        {
            ProviderId = created.WrappedKey.ProviderId,
            KeyId = created.WrappedKey.KeyId,
            Algorithm = created.WrappedKey.Algorithm,
            Ciphertext = truncated,
        };

        await Assert.ThrowsAsync<CryptographicException>(
            async () => await provider.UnwrapAsync(corrupt));
    }

    [Fact]
    public async Task WrongCiphertextLength_FailsBeforeAuthentication()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("a passphrase", TestDefaults.FastKek);
        using ContentKey created = await provider.CreateContentKeyAsync();

        // Tack on an extra byte so plaintextLength != 32. Should be rejected by the length defense.
        byte[] padded = new byte[created.WrappedKey.Ciphertext.Length + 1];
        created.WrappedKey.Ciphertext.AsSpan().CopyTo(padded);
        var corrupt = new WrappedContentKey
        {
            ProviderId = created.WrappedKey.ProviderId,
            KeyId = created.WrappedKey.KeyId,
            Algorithm = created.WrappedKey.Algorithm,
            Ciphertext = padded,
        };

        CryptographicException ex = await Assert.ThrowsAsync<CryptographicException>(
            async () => await provider.UnwrapAsync(corrupt));
        Assert.Contains("expected 32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnwrapWithUnknownKeyId_ThrowsKeyNotFound()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("a passphrase", TestDefaults.FastKek);
        using ContentKey created = await provider.CreateContentKeyAsync();

        var foreign = new WrappedContentKey
        {
            ProviderId = created.WrappedKey.ProviderId,
            KeyId = "local-deadbeefcafe",
            Algorithm = created.WrappedKey.Algorithm,
            Ciphertext = created.WrappedKey.Ciphertext,
        };

        await Assert.ThrowsAsync<KeyNotFoundException>(
            async () => await provider.UnwrapAsync(foreign));
    }
}
