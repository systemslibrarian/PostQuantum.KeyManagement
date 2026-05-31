using System.Security.Cryptography;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class KeyRotationTests
{
    [Fact]
    public async Task Rotate_ChangesActiveKey_ButKeepsOldKeysUnwrappable()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("first passphrase", TestDefaults.FastKek);
        string firstKeyId = provider.ActiveKeyId;

        using ContentKey legacy = await provider.CreateContentKeyAsync();
        byte[] legacyMaterial = legacy.Key.ToArray();

        string secondKeyId = provider.Rotate("second passphrase", TestDefaults.FastKek);

        Assert.NotEqual(firstKeyId, secondKeyId);
        Assert.Equal(secondKeyId, provider.ActiveKeyId);
        Assert.Equal(firstKeyId, legacy.WrappedKey.KeyId);

        // The key wrapped under the old KEK still unwraps after rotation.
        using ContentKey stillReadable = await provider.UnwrapAsync(legacy.WrappedKey);
        Assert.True(CryptographicOperations.FixedTimeEquals(legacyMaterial, stillReadable.Key));
    }

    [Fact]
    public async Task NewKeys_AfterRotation_UseTheNewActiveKek()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("first passphrase", TestDefaults.FastKek);
        string secondKeyId = provider.Rotate("second passphrase", TestDefaults.FastKek);

        using ContentKey fresh = await provider.CreateContentKeyAsync();

        Assert.Equal(secondKeyId, fresh.WrappedKey.KeyId);
    }

    [Fact]
    public async Task Rewrap_MovesKeyToActiveKek_WithoutChangingContentKey()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("first passphrase", TestDefaults.FastKek);
        string firstKeyId = provider.ActiveKeyId;

        using ContentKey created = await provider.CreateContentKeyAsync();
        byte[] originalMaterial = created.Key.ToArray();

        string secondKeyId = provider.Rotate("second passphrase", TestDefaults.FastKek);

        WrappedContentKey rewrapped = await provider.RewrapAsync(created.WrappedKey);

        // The wrap moved to the new KEK...
        Assert.Equal(firstKeyId, created.WrappedKey.KeyId);
        Assert.Equal(secondKeyId, rewrapped.KeyId);
        Assert.NotEqual(created.WrappedKey.Ciphertext, rewrapped.Ciphertext);

        // ...but the underlying content key is identical, so existing data stays decryptable.
        using ContentKey afterRewrap = await provider.UnwrapAsync(rewrapped);
        Assert.True(CryptographicOperations.FixedTimeEquals(originalMaterial, afterRewrap.Key));
    }

    [Fact]
    public async Task Unwrap_RejectsKeyFromAnotherProviderFamily()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("a passphrase", TestDefaults.FastKek);
        using ContentKey created = await provider.CreateContentKeyAsync();

        var foreign = new WrappedContentKey
        {
            ProviderId = "azure-key-vault",
            KeyId = created.WrappedKey.KeyId,
            Algorithm = created.WrappedKey.Algorithm,
            Ciphertext = created.WrappedKey.Ciphertext,
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await provider.UnwrapAsync(foreign));
    }
}
