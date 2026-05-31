using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class TryDecodeTests
{
    [Fact]
    public async Task WrappedContentKey_TryDecode_ReturnsTrueAndExactValueForValidToken()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p", TestDefaults.FastKek);
        using ContentKey k = await provider.CreateContentKeyAsync();
        string token = k.WrappedKey.Encode();

        Assert.True(WrappedContentKey.TryDecode(token, out WrappedContentKey? decoded));
        Assert.NotNull(decoded);
        Assert.Equal(k.WrappedKey.ProviderId, decoded!.ProviderId);
        Assert.Equal(k.WrappedKey.KeyId, decoded.KeyId);
        Assert.Equal(k.WrappedKey.Algorithm, decoded.Algorithm);
        Assert.Equal(k.WrappedKey.Ciphertext, decoded.Ciphertext);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-token!")]
    [InlineData("AQ")] // valid base64url but truncated body
    public void WrappedContentKey_TryDecode_ReturnsFalseForInvalidInput(string? token)
    {
        Assert.False(WrappedContentKey.TryDecode(token, out WrappedContentKey? decoded));
        Assert.Null(decoded);
    }

    [Fact]
    public void LocalKeyringMetadata_TryDecode_ReturnsTrueAndExactValueForValidToken()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p1", TestDefaults.FastKek);
        provider.Rotate("p2", TestDefaults.FastKek);
        string token = provider.ExportMetadata().Encode();

        Assert.True(LocalKeyringMetadata.TryDecode(token, out LocalKeyringMetadata? decoded));
        Assert.NotNull(decoded);
        Assert.Equal(2, decoded!.Keks.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage~!")]
    public void LocalKeyringMetadata_TryDecode_ReturnsFalseForInvalidInput(string? token)
    {
        Assert.False(LocalKeyringMetadata.TryDecode(token, out LocalKeyringMetadata? decoded));
        Assert.Null(decoded);
    }
}
