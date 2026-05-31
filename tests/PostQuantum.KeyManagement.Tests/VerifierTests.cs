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
            Assert.Equal(16, kek.Verifier!.Length);
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
