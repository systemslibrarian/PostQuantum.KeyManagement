using System.Security.Cryptography;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class AdvancedRotationTests
{
    [Fact]
    public async Task ManyRapidRotations_AllKeksRemainUnwrappable()
    {
        const int rotations = 25;
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p0", TestDefaults.FastKek);

        // Wrap a probe under each KEK as we rotate, then prove every probe still decrypts.
        var probes = new List<(WrappedContentKey wrapped, byte[] material, string keyId)>();
        for (int i = 0; i < rotations; i++)
        {
            using ContentKey k = await provider.CreateContentKeyAsync();
            probes.Add((k.WrappedKey, k.Key.ToArray(), provider.ActiveKeyId));
            provider.Rotate($"p{i + 1}", TestDefaults.FastKek);
        }

        foreach ((WrappedContentKey wrapped, byte[] material, string keyId) in probes)
        {
            Assert.Equal(keyId, wrapped.KeyId);
            using ContentKey r = await provider.UnwrapAsync(wrapped);
            Assert.True(CryptographicOperations.FixedTimeEquals(material, r.Key));
        }

        // Final keyring should hold the original + every rotation.
        LocalKeyringMetadata metadata = provider.ExportMetadata();
        Assert.Equal(rotations + 1, metadata.Keks.Count);
    }

    [Fact]
    public async Task ExportMetadata_ReflectsTheActiveKekAfterRotation()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p0", TestDefaults.FastKek);

        LocalKeyringMetadata first = provider.ExportMetadata();
        Assert.Equal(provider.ActiveKeyId, first.ActiveKeyId);
        Assert.Single(first.Keks);

        string newActive = provider.Rotate("p1", TestDefaults.FastKek);

        LocalKeyringMetadata after = provider.ExportMetadata();
        Assert.Equal(newActive, after.ActiveKeyId);
        Assert.Equal(2, after.Keks.Count);

        await Task.CompletedTask;
    }

    [Fact]
    public async Task RewrappedKey_StillRoundTripsToTheSameContentKey()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p0", TestDefaults.FastKek);
        using ContentKey originalKey = await provider.CreateContentKeyAsync();
        byte[] material = originalKey.Key.ToArray();

        // Rotate twice, rewrapping the original between rotations. Each rewrap should target the
        // most recently rotated KEK but the underlying content key must not change.
        provider.Rotate("p1", TestDefaults.FastKek);
        WrappedContentKey afterFirstRotation = await provider.RewrapAsync(originalKey.WrappedKey);
        Assert.Equal(provider.ActiveKeyId, afterFirstRotation.KeyId);

        provider.Rotate("p2", TestDefaults.FastKek);
        WrappedContentKey afterSecondRotation = await provider.RewrapAsync(afterFirstRotation);
        Assert.Equal(provider.ActiveKeyId, afterSecondRotation.KeyId);

        using ContentKey unwrappedAfterTwoHops = await provider.UnwrapAsync(afterSecondRotation);
        Assert.True(CryptographicOperations.FixedTimeEquals(material, unwrappedAfterTwoHops.Key));
    }

    [Fact]
    public async Task Import_OfMidLifecycleProvider_PreservesActiveKeyId()
    {
        // Create, rotate twice, export, then import — the active KEK on the imported provider
        // must match the last rotation, not the original.
        string token;
        string p0KeyId;
        string p1KeyId;
        string p2KeyId;
        WrappedContentKey wrappedUnderRotated;
        byte[] material;

        using (LocalContentKeyProvider source = LocalContentKeyProvider.Create("p0", TestDefaults.FastKek))
        {
            p0KeyId = source.ActiveKeyId;
            p1KeyId = source.Rotate("p1", TestDefaults.FastKek);
            p2KeyId = source.Rotate("p2", TestDefaults.FastKek);

            using ContentKey k = await source.CreateContentKeyAsync();
            wrappedUnderRotated = k.WrappedKey;
            material = k.Key.ToArray();
            token = source.ExportMetadata().Encode();
        }

        // Build a deterministic id → passphrase mapping rather than relying on ordering.
        Dictionary<string, string> passphrases = new(StringComparer.Ordinal)
        {
            [p0KeyId] = "p0",
            [p1KeyId] = "p1",
            [p2KeyId] = "p2",
        };

        LocalKeyringMetadata metadata = LocalKeyringMetadata.Decode(token);
        PassphraseResolver resolver = keyId => passphrases[keyId].AsSpan();

        using LocalContentKeyProvider restored = LocalContentKeyProvider.Import(metadata, resolver);
        Assert.Equal(p2KeyId, restored.ActiveKeyId);

        using ContentKey recovered = await restored.UnwrapAsync(wrappedUnderRotated);
        Assert.True(CryptographicOperations.FixedTimeEquals(material, recovered.Key));
    }
}
