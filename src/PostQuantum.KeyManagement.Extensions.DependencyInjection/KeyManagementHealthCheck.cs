using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace PostQuantum.KeyManagement.Extensions.DependencyInjection;

/// <summary>
/// A lightweight <see cref="IHealthCheck"/> that verifies the registered
/// <see cref="IContentKeyProvider"/> can complete a full wrap → unwrap round-trip. Useful as a
/// readiness probe in ASP.NET Core; degrades to <see cref="HealthStatus.Unhealthy"/> if the
/// provider raises an exception or fails to round-trip.
/// </summary>
/// <remarks>
/// Each invocation creates and immediately disposes a fresh 32-byte content key. With the local
/// provider this is a microsecond-scale AES-GCM operation; with a cloud KMS provider it is one
/// network round-trip and should be cached or rate-limited accordingly.
/// </remarks>
public sealed class KeyManagementHealthCheck : IHealthCheck
{
    private readonly IContentKeyProvider _provider;

    /// <summary>Creates a health check that exercises <paramref name="provider"/>.</summary>
    public KeyManagementHealthCheck(IContentKeyProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        _provider = provider;
    }

    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using ContentKey created = await _provider.CreateContentKeyAsync(cancellationToken).ConfigureAwait(false);
            using ContentKey recovered = await _provider.UnwrapAsync(created.WrappedKey, cancellationToken).ConfigureAwait(false);

            bool match = System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(created.Key, recovered.Key);
            return match
                ? HealthCheckResult.Healthy($"Active KEK: {_provider.ActiveKeyId}")
                : HealthCheckResult.Unhealthy("Provider round-trip produced mismatched key material.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return HealthCheckResult.Unhealthy("Provider round-trip threw.", ex);
        }
    }
}

/// <summary>
/// Extension method for registering <see cref="KeyManagementHealthCheck"/>.
/// </summary>
public static class KeyManagementHealthChecksBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="KeyManagementHealthCheck"/> against the host's
    /// <see cref="IContentKeyProvider"/> singleton.
    /// </summary>
    public static IHealthChecksBuilder AddPostQuantumKeyManagement(
        this IHealthChecksBuilder builder,
        string name = "post-quantum-key-management",
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddCheck<KeyManagementHealthCheck>(name, failureStatus, tags ?? []);
    }
}
