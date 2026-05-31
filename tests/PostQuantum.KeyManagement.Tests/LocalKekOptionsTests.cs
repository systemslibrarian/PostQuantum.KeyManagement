using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class LocalKekOptionsTests
{
    [Fact]
    public void Interactive_MatchesRfc9106SecondRecommendation()
    {
        LocalKekOptions opts = LocalKekOptions.Interactive;
        Assert.Equal(4, opts.DegreeOfParallelism);
        Assert.Equal(65536, opts.MemorySizeInKib);
        Assert.Equal(3, opts.Iterations);
    }

    [Fact]
    public void Sensitive_MatchesRfc9106FirstRecommendation()
    {
        LocalKekOptions opts = LocalKekOptions.Sensitive;
        Assert.Equal(4, opts.DegreeOfParallelism);
        Assert.Equal(2 * 1024 * 1024, opts.MemorySizeInKib);
        Assert.Equal(1, opts.Iterations);
    }

    [Fact]
    public void LowMemory_MatchesOwaspMinimum()
    {
        LocalKekOptions opts = LocalKekOptions.LowMemory;
        Assert.Equal(1, opts.DegreeOfParallelism);
        Assert.Equal(19 * 1024, opts.MemorySizeInKib);
        Assert.Equal(2, opts.Iterations);
    }

    [Fact]
    public void Defaults_MatchInteractive()
    {
        LocalKekOptions defaults = new();
        Assert.Equal(LocalKekOptions.Interactive.DegreeOfParallelism, defaults.DegreeOfParallelism);
        Assert.Equal(LocalKekOptions.Interactive.MemorySizeInKib, defaults.MemorySizeInKib);
        Assert.Equal(LocalKekOptions.Interactive.Iterations, defaults.Iterations);
        Assert.Equal(LocalKekOptions.Interactive.SaltSizeInBytes, defaults.SaltSizeInBytes);
    }

    [Theory]
    [InlineData(0, 1024, 1, 16)]
    [InlineData(1, 7, 1, 16)]
    [InlineData(1, 1024, 0, 16)]
    [InlineData(1, 1024, 1, 4)]
    public void Validate_RejectsOutOfRangeValues(int parallelism, int memory, int iterations, int saltSize)
    {
        LocalKekOptions opts = new()
        {
            DegreeOfParallelism = parallelism,
            MemorySizeInKib = memory,
            Iterations = iterations,
            SaltSizeInBytes = saltSize,
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => InvokeValidate(opts));
    }

    // Reach the internal Validate via reflection so we can hammer the boundary checks without
    // needing a public surface for them.
    private static void InvokeValidate(LocalKekOptions opts)
    {
        System.Reflection.MethodInfo method = typeof(LocalKekOptions).GetMethod(
            "Validate",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        try
        {
            method.Invoke(opts, null);
        }
        catch (System.Reflection.TargetInvocationException ex) when (ex.InnerException is not null)
        {
            throw ex.InnerException;
        }
    }
}
