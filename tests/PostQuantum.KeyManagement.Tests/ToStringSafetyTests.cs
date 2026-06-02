using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

/// <summary>
/// Verifies that the records' diagnostic <c>ToString()</c> output is safe to log: never includes
/// the raw byte arrays (which records' auto-generated <c>PrintMembers</c> would render as
/// <c>"System.Byte[]"</c>), and is short enough to be human-readable in an ops dashboard.
/// </summary>
public sealed class ToStringSafetyTests
{
    [Fact]
    public async Task WrappedContentKey_ToString_RedactsCiphertextBytes()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p", TestDefaults.FastKek);
        using ContentKey k = await provider.CreateContentKeyAsync();
        string s = k.WrappedKey.ToString();

        Assert.Contains("ProviderId = local", s, StringComparison.Ordinal);
        Assert.Contains(k.WrappedKey.KeyId, s, StringComparison.Ordinal);
        Assert.Contains("AES-256-GCM", s, StringComparison.Ordinal);
        Assert.Contains("Ciphertext = <", s, StringComparison.Ordinal);
        Assert.Contains(" bytes>", s, StringComparison.Ordinal);

        // The default record ToString would emit "System.Byte[]" for the array — we override that.
        Assert.DoesNotContain("System.Byte[]", s, StringComparison.Ordinal);

        // The full token shouldn't end up in the string.
        Assert.DoesNotContain(k.WrappedKey.Encode(), s, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalKekMetadata_ToString_RedactsSaltAndVerifierBytes()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p", TestDefaults.FastKek);
        LocalKekMetadata meta = provider.ExportMetadata().Keks[0];

        string s = meta.ToString();

        Assert.Contains($"KeyId = {meta.KeyId}", s, StringComparison.Ordinal);
        Assert.Contains("Salt = <16 bytes>", s, StringComparison.Ordinal);
        Assert.Contains("Verifier = <32 bytes>", s, StringComparison.Ordinal);
        Assert.Contains($"Iterations = {meta.Iterations}", s, StringComparison.Ordinal);
        Assert.DoesNotContain("System.Byte[]", s, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalKekMetadata_ToString_ShowsNullVerifier()
    {
        // Construct a metadata record without a verifier (the v1 token shape) to ensure the null
        // path is rendered cleanly rather than as the default "Verifier = " with nothing.
        LocalKekMetadata meta = new()
        {
            KeyId = "local-test",
            Salt = new byte[16],
            DegreeOfParallelism = 1,
            MemorySizeInKib = 1024,
            Iterations = 1,
            Verifier = null,
        };

        Assert.Contains("Verifier = null", meta.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void LocalKeyringMetadata_ToString_ShowsActiveAndCount_NotIndividualKeks()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p1", TestDefaults.FastKek);
        provider.Rotate("p2", TestDefaults.FastKek);

        LocalKeyringMetadata meta = provider.ExportMetadata();
        string s = meta.ToString();

        Assert.Contains($"ActiveKeyId = {meta.ActiveKeyId}", s, StringComparison.Ordinal);
        Assert.Contains("Keks.Count = 2", s, StringComparison.Ordinal);
        // Crucially: the byte arrays inside the KEK list shouldn't appear at all.
        Assert.DoesNotContain("System.Byte[]", s, StringComparison.Ordinal);
    }
}
