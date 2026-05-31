using Microsoft.Extensions.Options;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Extensions.DependencyInjection;
using PostQuantum.KeyManagement.Local;

namespace WorkerService.Sample;

/// <summary>
/// Periodically rotates the active KEK and persists the updated keyring through the registered
/// <see cref="IKeyringStore"/>. The new passphrase comes from configuration on each tick — in
/// production this is where you would integrate a secret manager that vends a fresh secret.
/// </summary>
/// <remarks>
/// This sample uses a deliberately short interval (configurable, defaulting to 2 minutes) so the
/// behaviour is visible during a demo. Production cadence is usually measured in days or weeks.
/// </remarks>
internal sealed class RotationWorker : BackgroundService
{
    private readonly IContentKeyProvider _provider;
    private readonly IKeyringStore? _store;
    private readonly IOptionsMonitor<RotationOptions> _options;
    private readonly IConfiguration _configuration;
    private readonly ILogger<RotationWorker> _log;

    public RotationWorker(
        IContentKeyProvider provider,
        IServiceProvider services,
        IOptionsMonitor<RotationOptions> options,
        IConfiguration configuration,
        ILogger<RotationWorker> log)
    {
        _provider = provider;
        _store = services.GetService<IKeyringStore>();
        _options = options;
        _configuration = configuration;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_provider is not LocalContentKeyProvider local)
        {
            _log.LogWarning(
                "RotationWorker only knows how to rotate LocalContentKeyProvider; {ProviderType} is something else. Exiting.",
                _provider.GetType().Name);
            return;
        }

        RotationOptions opts = _options.CurrentValue;
        TimeSpan interval = opts.Interval == TimeSpan.Zero ? TimeSpan.FromMinutes(2) : opts.Interval;
        _log.LogInformation("Rotation worker armed. Interval: {Interval}.", interval);

        using PeriodicTimer timer = new(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await RotateAsync(local, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Shutting down — normal.
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Rotation tick FAILED. Active KEK left unchanged: {ActiveKeyId}", local.ActiveKeyId);
            }
        }
    }

    private async Task RotateAsync(LocalContentKeyProvider local, CancellationToken cancellationToken)
    {
        // In production, the new passphrase comes from a secret manager. For the sample we just
        // append the tick counter to the existing passphrase so the demo can show rotation working
        // without prompting; do NOT do this in production.
        string previousActive = local.ActiveKeyId;
        string newPassphrase = _configuration["KeyManagement:Passphrase"] + "-rotation-" + DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        string newActive = local.Rotate(newPassphrase);
        _log.LogInformation(
            "Rotated KEK: {PreviousActive} -> {NewActive}.", previousActive, newActive);

        if (_store is not null)
        {
            await _store.SaveAsync(local.ExportMetadata().Encode(), cancellationToken).ConfigureAwait(false);
            _log.LogInformation("Persisted updated keyring to the configured store.");
        }
    }
}

internal sealed class RotationOptions
{
    public TimeSpan Interval { get; set; }
}
