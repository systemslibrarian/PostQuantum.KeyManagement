using System.Security.Cryptography;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class PassphraseEdgeCaseTests
{
    [Fact]
    public async Task LongPassphrase_DerivesAndRoundTrips()
    {
        // 8 KiB passphrase — well past any reasonable real-world length, exercises the UTF-8
        // conversion and zeroing paths.
        string passphrase = new('x', 8 * 1024);

        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create(passphrase, TestDefaults.FastKek);
        using ContentKey k = await provider.CreateContentKeyAsync();
        using ContentKey r = await provider.UnwrapAsync(k.WrappedKey);

        Assert.True(CryptographicOperations.FixedTimeEquals(k.Key, r.Key));
    }

    [Fact]
    public async Task UnicodePassphrase_DerivesAndRoundTrips()
    {
        // Mix of BMP, supplementary plane, RTL, and emoji — all valid Unicode that flows through
        // Encoding.UTF8.GetBytes(ReadOnlySpan<char>, Span<byte>).
        const string passphrase = "ƒ ω σ Δ ‒ مرحبا ‒ 🔑🛡️🔥 ‒ 中文";

        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create(passphrase, TestDefaults.FastKek);
        using ContentKey k = await provider.CreateContentKeyAsync();
        using ContentKey r = await provider.UnwrapAsync(k.WrappedKey);

        Assert.True(CryptographicOperations.FixedTimeEquals(k.Key, r.Key));
    }

    [Fact]
    public async Task UnicodePassphrase_RoundTripsAcrossKeyringExportImport()
    {
        const string passphrase = "أهلا — 🔐 — 鍵管理";
        string token;
        WrappedContentKey wrapped;
        byte[] material;

        using (LocalContentKeyProvider source = LocalContentKeyProvider.Create(passphrase, TestDefaults.FastKek))
        {
            using ContentKey k = await source.CreateContentKeyAsync();
            wrapped = k.WrappedKey;
            material = k.Key.ToArray();
            token = source.ExportMetadata().Encode();
        }

        LocalKeyringMetadata metadata = LocalKeyringMetadata.Decode(token);
        using LocalContentKeyProvider restored = LocalContentKeyProvider.Import(metadata, _ => passphrase.AsSpan());
        using ContentKey recovered = await restored.UnwrapAsync(wrapped);

        Assert.True(CryptographicOperations.FixedTimeEquals(material, recovered.Key));
    }

    [Fact]
    public void EmptyPassphrase_IsRejectedAtTheLibraryBoundary()
    {
        // Empty passphrases offer no entropy. The library refuses them with a clear
        // ArgumentException before any cryptographic work runs.
        byte[] salt = RandomNumberGenerator.GetBytes(16);

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => LocalContentKeyProvider.Create("", salt, TestDefaults.FastKek));
        Assert.Equal("passphrase", ex.ParamName);
    }

    [Fact]
    public void EmptyRotationPassphrase_IsRejected()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p", TestDefaults.FastKek);
        Assert.Throws<ArgumentException>(() => provider.Rotate(""));
    }
}
