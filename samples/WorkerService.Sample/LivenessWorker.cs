using System.Security.Cryptography;
using PostQuantum.KeyManagement;

namespace WorkerService.Sample;

/// <summary>
/// On a fixed interval, mints a content key, encrypts a probe payload with it, then immediately
/// unwraps it and decrypts — proving the provider is functional end-to-end. Logs are intentionally
/// structured so an ops dashboard can scrape KEK id + duration.
/// </summary>
internal sealed class LivenessWorker : BackgroundService
{
    private static readonly byte[] Probe = "liveness-probe"u8.ToArray();
    private readonly IContentKeyProvider _provider;
    private readonly ILogger<LivenessWorker> _log;

    public LivenessWorker(IContentKeyProvider provider, ILogger<LivenessWorker> log)
    {
        _provider = provider;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("Liveness worker starting. Initial active KEK: {ActiveKeyId}", _provider.ActiveKeyId);

        using PeriodicTimer timer = new(TimeSpan.FromSeconds(10));
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            long started = System.Diagnostics.Stopwatch.GetTimestamp();
            try
            {
                await RoundTripAsync(stoppingToken).ConfigureAwait(false);
                double elapsedMs = System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                _log.LogInformation(
                    "Liveness probe OK in {ElapsedMs:F1} ms. Active KEK: {ActiveKeyId}",
                    elapsedMs, _provider.ActiveKeyId);
            }
            catch (OperationCanceledException)
            {
                // Shutting down — normal.
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Liveness probe FAILED. Active KEK: {ActiveKeyId}", _provider.ActiveKeyId);
            }
        }
    }

    private async Task RoundTripAsync(CancellationToken cancellationToken)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        byte[] ciphertext = new byte[Probe.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

        WrappedContentKey wrapped;
        using (ContentKey k = await _provider.CreateContentKeyAsync(cancellationToken).ConfigureAwait(false))
        {
            using var aes = new AesGcm(k.Key, tag.Length);
            aes.Encrypt(nonce, Probe, ciphertext, tag);
            wrapped = k.WrappedKey;
        }

        byte[] plaintext = new byte[ciphertext.Length];
        using (ContentKey k = await _provider.UnwrapAsync(wrapped, cancellationToken).ConfigureAwait(false))
        {
            using var aes = new AesGcm(k.Key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        if (!plaintext.AsSpan().SequenceEqual(Probe.AsSpan()))
        {
            throw new CryptographicException("Round-trip plaintext did not match the probe.");
        }
    }
}
