using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Extensions.DependencyInjection;
using Xunit;

namespace PostQuantum.KeyManagement.Extensions.DependencyInjection.Tests;

public sealed class ServiceCollectionExtensionsTests
{
    [Fact]
    public async Task AddPostQuantumKeyManagement_RegistersAFunctionalProvider()
    {
        ServiceCollection services = new();
        services.AddPostQuantumKeyManagement(o =>
        {
            o.Passphrase = "test passphrase";
            o.WorkFactor = KekWorkFactor.LowMemory;
        });

        await using ServiceProvider sp = services.BuildServiceProvider();
        IContentKeyProvider provider = sp.GetRequiredService<IContentKeyProvider>();

        using ContentKey key = await provider.CreateContentKeyAsync();
        using ContentKey roundTrip = await provider.UnwrapAsync(key.WrappedKey);
        Assert.True(CryptographicOperations.FixedTimeEquals(key.Key, roundTrip.Key));
    }

    [Fact]
    public void MissingPassphrase_ThrowsAtResolution()
    {
        ServiceCollection services = new();
        services.AddPostQuantumKeyManagement(o => { o.WorkFactor = KekWorkFactor.LowMemory; });

        using ServiceProvider sp = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<IContentKeyProvider>());
    }

    [Fact]
    public void Provider_IsRegisteredAsSingleton()
    {
        ServiceCollection services = new();
        services.AddPostQuantumKeyManagement(o =>
        {
            o.Passphrase = "test";
            o.WorkFactor = KekWorkFactor.LowMemory;
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        IContentKeyProvider a = sp.GetRequiredService<IContentKeyProvider>();
        IContentKeyProvider b = sp.GetRequiredService<IContentKeyProvider>();
        Assert.Same(a, b);
    }

    [Fact]
    public async Task KeyringPath_PersistsRingAcrossHostBuilds()
    {
        string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"pqkm-test-{Guid.NewGuid():N}.bin");
        try
        {
            WrappedContentKey wrapped;
            byte[] material;
            string activeId;

            // ── First "process": create + wrap + persist. ──
            {
                ServiceCollection services = new();
                services.AddPostQuantumKeyManagement(o =>
                {
                    o.Passphrase = "test";
                    o.WorkFactor = KekWorkFactor.LowMemory;
                    o.KeyringPath = path;
                });

                await using ServiceProvider sp = services.BuildServiceProvider();
                IContentKeyProvider provider = sp.GetRequiredService<IContentKeyProvider>();
                activeId = provider.ActiveKeyId;

                using ContentKey key = await provider.CreateContentKeyAsync();
                wrapped = key.WrappedKey;
                material = key.Key.ToArray();
            }

            Assert.True(File.Exists(path));

            // ── Second "process": same path + passphrase, must unwrap the earlier key. ──
            {
                ServiceCollection services = new();
                services.AddPostQuantumKeyManagement(o =>
                {
                    o.Passphrase = "test";
                    o.WorkFactor = KekWorkFactor.LowMemory;
                    o.KeyringPath = path;
                });

                await using ServiceProvider sp = services.BuildServiceProvider();
                IContentKeyProvider provider = sp.GetRequiredService<IContentKeyProvider>();
                Assert.Equal(activeId, provider.ActiveKeyId);

                using ContentKey recovered = await provider.UnwrapAsync(wrapped);
                Assert.True(CryptographicOperations.FixedTimeEquals(material, recovered.Key));
            }
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
