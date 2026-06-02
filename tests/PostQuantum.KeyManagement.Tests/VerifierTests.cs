using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class VerifierTests
{
    [Fact]
    public void Export_PopulatesVerifierForEveryKek()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p1", TestDefaults.FastKek);
        provider.Rotate("p2", TestDefaults.FastKek);

        LocalKeyringMetadata metadata = provider.ExportMetadata();

        Assert.Equal(2, metadata.Keks.Count);
        foreach (LocalKekMetadata kek in metadata.Keks)
        {
            Assert.NotNull(kek.Verifier);
            Assert.Equal(32, kek.Verifier!.Length);
            Assert.Contains(kek.Verifier, b => b != 0); // sanity: not all-zero
        }
    }

    [Fact]
    public void Import_WithWrongPassphrase_FailsAtImport_NotAtUnwrap()
    {
        string token;
        string keyId;
        using (LocalContentKeyProvider source = LocalContentKeyProvider.Create("the right passphrase", TestDefaults.FastKek))
        {
            keyId = source.ActiveKeyId;
            token = source.ExportMetadata().Encode();
        }

        LocalKeyringMetadata metadata = LocalKeyringMetadata.Decode(token);
        PassphraseResolver wrong = _ => "the WRONG passphrase".AsSpan();

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => LocalContentKeyProvider.Import(metadata, wrong));
        Assert.Contains("Verifier mismatch", ex.Message, StringComparison.Ordinal);
        Assert.Contains(keyId, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Import_WithCorrectPassphrase_PassesVerifierAndUnwraps()
    {
        string token;
        WrappedContentKey wrapped;
        byte[] material;
        using (LocalContentKeyProvider source = LocalContentKeyProvider.Create("good passphrase", TestDefaults.FastKek))
        {
            using ContentKey created = await source.CreateContentKeyAsync();
            wrapped = created.WrappedKey;
            material = created.Key.ToArray();
            token = source.ExportMetadata().Encode();
        }

        LocalKeyringMetadata metadata = LocalKeyringMetadata.Decode(token);
        PassphraseResolver correct = _ => "good passphrase".AsSpan();

        using LocalContentKeyProvider restored = LocalContentKeyProvider.Import(metadata, correct);
        using ContentKey unwrapped = await restored.UnwrapAsync(wrapped);

        Assert.True(System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(material, unwrapped.Key));
    }

    [Fact]
    public async Task Import_FromV2Token_With16ByteVerifier_StillImports()
    {
        // Hand-craft a v2 token (16-byte truncated verifier) and prove the v3 reader's
        // prefix-compare path accepts the correct passphrase and rejects a wrong one.
        WrappedContentKey wrapped;
        byte[] material;
        LocalKeyringMetadata current;
        using (LocalContentKeyProvider source = LocalContentKeyProvider.Create("v2-passphrase", TestDefaults.FastKek))
        {
            using ContentKey created = await source.CreateContentKeyAsync();
            wrapped = created.WrappedKey;
            material = created.Key.ToArray();
            current = source.ExportMetadata();
        }

        string v2Token = EncodeAsV2WithTruncatedVerifier(current);
        LocalKeyringMetadata decoded = LocalKeyringMetadata.Decode(v2Token);
        Assert.Single(decoded.Keks);
        Assert.NotNull(decoded.Keks[0].Verifier);
        Assert.Equal(16, decoded.Keks[0].Verifier!.Length);

        // Correct passphrase: prefix-compare must accept the 16-byte verifier.
        using LocalContentKeyProvider restored = LocalContentKeyProvider.Import(
            decoded, _ => "v2-passphrase".AsSpan());
        using ContentKey unwrapped = await restored.UnwrapAsync(wrapped);
        Assert.True(System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(material, unwrapped.Key));

        // Wrong passphrase: the prefix-compare must still detect the mismatch up front.
        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => LocalContentKeyProvider.Import(decoded, _ => "the WRONG passphrase".AsSpan()));
        Assert.Contains("Verifier mismatch", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Import_FromLegacyV1Token_WithoutVerifier_StillImports()
    {
        // Hand-craft a v1 token (no verifier field) to prove backward compatibility.
        using LocalContentKeyProvider source = LocalContentKeyProvider.Create("p", TestDefaults.FastKek);
        WrappedContentKey wrapped;
        byte[] material;
        using (ContentKey created = await source.CreateContentKeyAsync())
        {
            wrapped = created.WrappedKey;
            material = created.Key.ToArray();
        }

        LocalKeyringMetadata current = source.ExportMetadata();
        string v1Token = EncodeAsV1(current);

        LocalKeyringMetadata decoded = LocalKeyringMetadata.Decode(v1Token);
        Assert.Single(decoded.Keks);
        Assert.Null(decoded.Keks[0].Verifier);

        // A v1 token has no verifier, so Import cannot detect a wrong passphrase up front — but the
        // right passphrase still imports successfully and unwrap still works.
        using LocalContentKeyProvider restored = LocalContentKeyProvider.Import(
            decoded, _ => "p".AsSpan());
        using ContentKey unwrapped = await restored.UnwrapAsync(wrapped);

        Assert.True(System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(material, unwrapped.Key));
    }

    private static string EncodeAsV1(LocalKeyringMetadata metadata)
    {
        using var buffer = new MemoryStream();
        buffer.WriteByte(0x01); // legacy FormatVersion
        WriteString(buffer, metadata.ActiveKeyId);
        WriteInt32(buffer, metadata.Keks.Count);
        foreach (LocalKekMetadata kek in metadata.Keks)
        {
            WriteString(buffer, kek.KeyId);
            WriteBytes(buffer, kek.Salt);
            WriteInt32(buffer, kek.DegreeOfParallelism);
            WriteInt32(buffer, kek.MemorySizeInKib);
            WriteInt32(buffer, kek.Iterations);
            // v1 deliberately omits the verifier field.
        }

        return Convert.ToBase64String(buffer.ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string EncodeAsV2WithTruncatedVerifier(LocalKeyringMetadata metadata)
    {
        using var buffer = new MemoryStream();
        buffer.WriteByte(0x02); // v2 FormatVersion
        WriteString(buffer, metadata.ActiveKeyId);
        WriteInt32(buffer, metadata.Keks.Count);
        foreach (LocalKekMetadata kek in metadata.Keks)
        {
            WriteString(buffer, kek.KeyId);
            WriteBytes(buffer, kek.Salt);
            WriteInt32(buffer, kek.DegreeOfParallelism);
            WriteInt32(buffer, kek.MemorySizeInKib);
            WriteInt32(buffer, kek.Iterations);
            // v2 persisted the first 16 bytes of the same HMAC-SHA256 the v3 reader recomputes,
            // so the v3 reader's prefix-compare path must accept it.
            byte[] truncated = (kek.Verifier ?? []).AsSpan(0, Math.Min(16, kek.Verifier?.Length ?? 0)).ToArray();
            WriteBytes(buffer, truncated);
        }

        return Convert.ToBase64String(buffer.ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static void WriteInt32(Stream stream, int value)
    {
        Span<byte> b = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(b, value);
        stream.Write(b);
    }

    private static void WriteBytes(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteInt32(stream, value.Length);
        stream.Write(value);
    }

    private static void WriteString(Stream stream, string value)
        => WriteBytes(stream, System.Text.Encoding.UTF8.GetBytes(value));
}
