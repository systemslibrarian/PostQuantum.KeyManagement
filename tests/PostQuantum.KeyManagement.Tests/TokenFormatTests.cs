using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

/// <summary>
/// Tests that the wire formats (<see cref="WrappedContentKey"/>, <see cref="LocalKeyringMetadata"/>)
/// reject malformed and adversarial inputs.
/// </summary>
public sealed class TokenFormatTests
{
    [Fact]
    public void WrappedContentKey_Decode_RejectsGarbage()
    {
        Assert.Throws<FormatException>(() => WrappedContentKey.Decode("not-a-token!"));
    }

    [Fact]
    public void WrappedContentKey_Decode_RejectsEmpty()
    {
        Assert.Throws<ArgumentException>(() => WrappedContentKey.Decode(string.Empty));
    }

    [Fact]
    public void WrappedContentKey_Decode_RejectsTruncatedHeader()
    {
        // A single-byte token: declares version but has no fields.
        string token = ToBase64Url([0x01]);
        Assert.Throws<FormatException>(() => WrappedContentKey.Decode(token));
    }

    [Fact]
    public void WrappedContentKey_Decode_RejectsUnknownVersion()
    {
        string token = ToBase64Url([0xFF, 0x00, 0x00, 0x00, 0x00]);
        Assert.Throws<FormatException>(() => WrappedContentKey.Decode(token));
    }

    [Fact]
    public void WrappedContentKey_Decode_RejectsOverflowLengthPrefix()
    {
        // Version 1, followed by an int32 length prefix = int.MaxValue. Naive `offset + length` would
        // overflow to negative and pass the bounds check; the overflow-safe subtraction must reject it.
        byte[] data =
        [
            0x01, // FormatVersion
            0x7F, 0xFF, 0xFF, 0xFF, // ProviderId length = int.MaxValue
        ];
        Assert.Throws<FormatException>(() => WrappedContentKey.Decode(ToBase64Url(data)));
    }

    [Fact]
    public void WrappedContentKey_Decode_RejectsNegativeLengthPrefix()
    {
        byte[] data =
        [
            0x01,
            0xFF, 0xFF, 0xFF, 0xFF, // length = -1
        ];
        Assert.Throws<FormatException>(() => WrappedContentKey.Decode(ToBase64Url(data)));
    }

    [Fact]
    public void KeyringMetadata_Decode_RejectsOverlargeKekCount()
    {
        // Version 2, ActiveKeyId of length 0, then a KEK count above the cap.
        byte[] data =
        [
            LocalKeyringMetadata.CurrentFormatVersion,
            0x00, 0x00, 0x00, 0x00, // ActiveKeyId = ""
            0x00, 0x10, 0x00, 0x01, // KEK count = 1048577 (above MaxKekCount = 1024)
        ];
        Assert.Throws<FormatException>(() => LocalKeyringMetadata.Decode(ToBase64Url(data)));
    }

    [Fact]
    public void KeyringMetadata_Decode_RejectsNegativeKekCount()
    {
        byte[] data =
        [
            LocalKeyringMetadata.CurrentFormatVersion,
            0x00, 0x00, 0x00, 0x00, // ActiveKeyId = ""
            0xFF, 0xFF, 0xFF, 0xFF, // KEK count = -1
        ];
        Assert.Throws<FormatException>(() => LocalKeyringMetadata.Decode(ToBase64Url(data)));
    }

    [Fact]
    public void KeyringMetadata_Decode_RejectsUnknownVersion()
    {
        string token = ToBase64Url([0xEE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        Assert.Throws<FormatException>(() => LocalKeyringMetadata.Decode(token));
    }

    private static string ToBase64Url(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
