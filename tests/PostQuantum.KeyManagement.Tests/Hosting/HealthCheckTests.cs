using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace PostQuantum.KeyManagement.Tests.Hosting;

public sealed class HealthCheckTests
{
    [Fact]
    public async Task HealthCheck_ReportsHealthyForAWorkingProvider()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddPostQuantumKeyManagement(o =>
        {
            o.Passphrase = "test";
            o.WorkFactor = KekWorkFactor.LowMemory;
        });
        services.AddHealthChecks().AddPostQuantumKeyManagement();

        await using ServiceProvider sp = services.BuildServiceProvider();
        HealthCheckService svc = sp.GetRequiredService<HealthCheckService>();

        HealthReport report = await svc.CheckHealthAsync();

        Assert.Equal(HealthStatus.Healthy, report.Status);
        Assert.True(report.Entries["post-quantum-key-management"].Description!.Contains("local-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task HealthCheck_ReportsUnhealthyWhenProviderThrows()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IContentKeyProvider, ThrowingProvider>();
        services.AddHealthChecks().AddPostQuantumKeyManagement();

        await using ServiceProvider sp = services.BuildServiceProvider();
        HealthCheckService svc = sp.GetRequiredService<HealthCheckService>();

        HealthReport report = await svc.CheckHealthAsync();

        Assert.Equal(HealthStatus.Unhealthy, report.Status);
    }

    private sealed class ThrowingProvider : IContentKeyProvider
    {
        public string ProviderId => "throwing";
        public string ActiveKeyId => "k";
        public ValueTask<ContentKey> CreateContentKeyAsync(CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom");
        public ValueTask<ContentKey> UnwrapAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom");
        public ValueTask<WrappedContentKey> RewrapAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom");
    }
}
