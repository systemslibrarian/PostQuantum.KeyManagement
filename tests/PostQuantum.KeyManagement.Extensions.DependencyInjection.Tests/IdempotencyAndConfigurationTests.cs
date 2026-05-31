using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Extensions.DependencyInjection;
using Xunit;

namespace PostQuantum.KeyManagement.Extensions.DependencyInjection.Tests;

public sealed class IdempotencyAndConfigurationTests
{
    [Fact]
    public async Task AddPostQuantumKeyManagement_IsIdempotent()
    {
        // Calling AddPostQuantumKeyManagement twice with the same configuration should not produce
        // duplicate service registrations.
        ServiceCollection services = new();
        services.AddPostQuantumKeyManagement(o =>
        {
            o.Passphrase = "p";
            o.WorkFactor = KekWorkFactor.LowMemory;
        });
        services.AddPostQuantumKeyManagement(o =>
        {
            o.Passphrase = "p";
            o.WorkFactor = KekWorkFactor.LowMemory;
        });

        int registrations = services.Count(s => s.ServiceType == typeof(IContentKeyProvider));
        Assert.Equal(1, registrations);

        await using ServiceProvider sp = services.BuildServiceProvider();
        IContentKeyProvider provider = sp.GetRequiredService<IContentKeyProvider>();
        using ContentKey k = await provider.CreateContentKeyAsync();
        Assert.NotEqual(0, k.Key.Length);
    }

    [Fact]
    public async Task ConfigurationBinding_FromIConfiguration_Works()
    {
        // Simulate the typical ASP.NET Core pattern where options are bound from IConfiguration
        // before AddPostQuantumKeyManagement() runs.
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["KeyManagement:Passphrase"] = "bound-from-config",
                ["KeyManagement:WorkFactor"] = nameof(KekWorkFactor.LowMemory),
            })
            .Build();

        ServiceCollection services = new();
        services.AddOptions<KeyManagementOptions>()
            .Bind(configuration.GetSection("KeyManagement"));
        services.AddPostQuantumKeyManagement();

        await using ServiceProvider sp = services.BuildServiceProvider();
        KeyManagementOptions bound = sp.GetRequiredService<IOptions<KeyManagementOptions>>().Value;
        Assert.Equal("bound-from-config", bound.Passphrase);
        Assert.Equal(KekWorkFactor.LowMemory, bound.WorkFactor);

        IContentKeyProvider provider = sp.GetRequiredService<IContentKeyProvider>();
        using ContentKey k = await provider.CreateContentKeyAsync();
        using ContentKey r = await provider.UnwrapAsync(k.WrappedKey);
        Assert.True(CryptographicOperations.FixedTimeEquals(k.Key, r.Key));
    }

    [Fact]
    public async Task KeyringPath_RelativePath_Resolves()
    {
        string path = Path.Combine("test-keyrings", $"k-{Guid.NewGuid():N}.bin");
        try
        {
            ServiceCollection services = new();
            services.AddPostQuantumKeyManagement(o =>
            {
                o.Passphrase = "p";
                o.WorkFactor = KekWorkFactor.LowMemory;
                o.KeyringPath = path;
            });

            await using ServiceProvider sp = services.BuildServiceProvider();
            IContentKeyProvider provider = sp.GetRequiredService<IContentKeyProvider>();
            using ContentKey k = await provider.CreateContentKeyAsync();
            Assert.NotEqual(0, k.Key.Length);

            // Should have created the directory and the file.
            Assert.True(File.Exists(path));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
            {
                Directory.Delete(dir);
            }
        }
    }
}
