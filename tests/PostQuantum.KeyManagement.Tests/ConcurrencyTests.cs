using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.KeyManagement.Tests;

public sealed class ConcurrencyTests
{
    [Fact]
    public async Task ConcurrentWrapUnwrap_AcrossManyTasks_AlwaysRoundTrips()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p", TestDefaults.FastKek);

        Task[] workers = new Task[Environment.ProcessorCount * 2];
        for (int i = 0; i < workers.Length; i++)
        {
            workers[i] = Task.Run(async () =>
            {
                for (int j = 0; j < 50; j++)
                {
                    using ContentKey k = await provider.CreateContentKeyAsync();
                    byte[] original = k.Key.ToArray();
                    using ContentKey r = await provider.UnwrapAsync(k.WrappedKey);
                    Assert.True(System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(original, r.Key));
                }
            });
        }

        await Task.WhenAll(workers);
    }

    [Fact]
    public async Task ConcurrentUnwrap_WhileRotating_OldKeysStayUnwrappable()
    {
        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p1", TestDefaults.FastKek);

        // Capture a fleet of wrapped keys made under the first KEK.
        var wraps = new List<(WrappedContentKey wrapped, byte[] material)>();
        for (int i = 0; i < 40; i++)
        {
            using ContentKey k = await provider.CreateContentKeyAsync();
            wraps.Add((k.WrappedKey, k.Key.ToArray()));
        }

        // Hammer the provider from many threads while a single rotator thread rotates several times.
        using var cancel = new CancellationTokenSource();
        Task rotator = Task.Run(() =>
        {
            for (int i = 0; i < 5 && !cancel.IsCancellationRequested; i++)
            {
                provider.Rotate($"rotated-p{i}", TestDefaults.FastKek);
            }
        });

        Task[] readers = new Task[Environment.ProcessorCount * 2];
        for (int i = 0; i < readers.Length; i++)
        {
            readers[i] = Task.Run(async () =>
            {
                for (int iter = 0; iter < 100; iter++)
                {
                    foreach ((WrappedContentKey wrapped, byte[] material) in wraps)
                    {
                        using ContentKey r = await provider.UnwrapAsync(wrapped);
                        Assert.True(System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(material, r.Key));
                    }
                }
            });
        }

        await Task.WhenAll(readers);
        await rotator;
        cancel.Cancel();
    }

    [Fact]
    public async Task DisposedProvider_ThrowsObjectDisposed()
    {
        LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p", TestDefaults.FastKek);
        provider.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = provider.ActiveKeyId);
        Assert.Throws<ObjectDisposedException>(() => _ = provider.ActiveSalt);
        Assert.Throws<ObjectDisposedException>(() => provider.ExportMetadata());
        await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await provider.CreateContentKeyAsync());
    }

    [Fact]
    public void Rotate_WithCollidingSalt_ThrowsAndPreservesActiveKek()
    {
        byte[] salt = new byte[16];
        for (int i = 0; i < salt.Length; i++)
        {
            salt[i] = (byte)i;
        }

        using LocalContentKeyProvider provider = LocalContentKeyProvider.Create("p1", salt, TestDefaults.FastKek);
        string original = provider.ActiveKeyId;

        Assert.Throws<InvalidOperationException>(() => provider.Rotate("p2", salt, TestDefaults.FastKek));
        Assert.Equal(original, provider.ActiveKeyId);
    }
}
