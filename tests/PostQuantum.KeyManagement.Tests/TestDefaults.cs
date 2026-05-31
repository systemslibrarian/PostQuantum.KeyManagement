using PostQuantum.KeyManagement.Local;

namespace PostQuantum.KeyManagement.Tests;

/// <summary>
/// Shared test fixtures. Argon2id work factors are deliberately tiny here so the suite runs fast;
/// production code should use the library defaults (or stronger).
/// </summary>
internal static class TestDefaults
{
    public static LocalKekOptions FastKek { get; } = new()
    {
        DegreeOfParallelism = 1,
        MemorySizeInKib = 1024,
        Iterations = 1,
        SaltSizeInBytes = 16,
    };
}
