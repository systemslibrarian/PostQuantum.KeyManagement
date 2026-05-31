using System.Security.Cryptography;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class KeyringPersistenceTests
{
    [Fact]
    public async Task ExportImport_SurvivesProcessRestart_AndUnwrapsKeysFromEveryKek()
    {
        string token;
        WrappedContentKey legacyWrapped;
        WrappedContentKey currentWrapped;
        byte[] legacyMaterial;
        byte[] currentMaterial;
        string firstKeyId;
        string secondKeyId;

        // ── "First process": create, rotate, wrap under both KEKs, then export the keyring. ──
        using (LocalContentKeyProvider provider = LocalContentKeyProvider.Create("first passphrase", TestDefaults.FastKek))
        {
            firstKeyId = provider.ActiveKeyId;
            using (ContentKey legacy = await provider.CreateContentKeyAsync())
            {
                legacyWrapped = legacy.WrappedKey;
                legacyMaterial = legacy.Key.ToArray();
            }

            secondKeyId = provider.Rotate("second passphrase", TestDefaults.FastKek);
            using (ContentKey current = await provider.CreateContentKeyAsync())
            {
                currentWrapped = current.WrappedKey;
                currentMaterial = current.Key.ToArray();
            }

            token = provider.ExportMetadata().Encode();
        }

        // ── "Second process": rebuild from the token, supplying each KEK's passphrase. ──
        LocalKeyringMetadata metadata = LocalKeyringMetadata.Decode(token);
        PassphraseResolver resolver = keyId =>
            string.Equals(keyId, firstKeyId, StringComparison.Ordinal)
                ? "first passphrase".AsSpan()
                : "second passphrase".AsSpan();

        using LocalContentKeyProvider restored = LocalContentKeyProvider.Import(metadata, resolver);

        Assert.Equal(secondKeyId, restored.ActiveKeyId);

        // A key wrapped under the rotated-out KEK still unwraps...
        using (ContentKey legacy = await restored.UnwrapAsync(legacyWrapped))
        {
            Assert.True(CryptographicOperations.FixedTimeEquals(legacyMaterial, legacy.Key));
        }

        // ...and so does one wrapped under the active KEK.
        using (ContentKey current = await restored.UnwrapAsync(currentWrapped))
        {
            Assert.True(CryptographicOperations.FixedTimeEquals(currentMaterial, current.Key));
        }
    }

    [Fact]
    public void KeyringMetadata_EncodeDecode_RoundTripsEveryField()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p1", TestDefaults.FastKek);
        provider.Rotate("p2", TestDefaults.FastKek);

        LocalKeyringMetadata original = provider.ExportMetadata();
        LocalKeyringMetadata decoded = LocalKeyringMetadata.Decode(original.Encode());

        Assert.Equal(original.ActiveKeyId, decoded.ActiveKeyId);
        Assert.Equal(2, decoded.Keks.Count);
        for (int i = 0; i < original.Keks.Count; i++)
        {
            Assert.Equal(original.Keks[i].KeyId, decoded.Keks[i].KeyId);
            Assert.Equal(original.Keks[i].Salt, decoded.Keks[i].Salt);
            Assert.Equal(original.Keks[i].DegreeOfParallelism, decoded.Keks[i].DegreeOfParallelism);
            Assert.Equal(original.Keks[i].MemorySizeInKib, decoded.Keks[i].MemorySizeInKib);
            Assert.Equal(original.Keks[i].Iterations, decoded.Keks[i].Iterations);
        }
    }

    [Fact]
    public void Import_Throws_WhenActiveKeyIdIsNotInTheRing()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p", TestDefaults.FastKek);
        LocalKeyringMetadata broken = provider.ExportMetadata() with { ActiveKeyId = "local-000000000000" };

        PassphraseResolver resolver = _ => "p".AsSpan();

        Assert.Throws<InvalidOperationException>(() => LocalContentKeyProvider.Import(broken, resolver));
    }
}
