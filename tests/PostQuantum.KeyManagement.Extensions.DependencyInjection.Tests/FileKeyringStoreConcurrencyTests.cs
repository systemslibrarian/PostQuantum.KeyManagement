using PostQuantum.KeyManagement.Extensions.DependencyInjection;
using Xunit;

namespace PostQuantum.KeyManagement.Extensions.DependencyInjection.Tests;

/// <summary>
/// Exercises the atomic-write paths in <see cref="FileKeyringStore"/>:
/// the first-write race that lands in the <c>FileNotFoundException</c> → <c>Move</c> branch (and
/// the TOCTOU fall-back to <c>Replace</c> when two writers both see the file as missing), and the
/// single-writer-multiple-readers shape that the deployment guide documents as the production model.
/// </summary>
public sealed class FileKeyringStoreConcurrencyTests
{
    [Fact]
    public async Task FirstWriteRace_BetweenTwoWriters_BothSucceed_AndOnePayloadWins()
    {
        // Two writers, fresh path, both call SaveAsync once. One ends up in the FileNotFound →
        // Move path; the other, depending on timing, lands in TOCTOU → Replace. Both must
        // complete without throwing, and the file must contain exactly one of the two payloads.
        string path = NewTempPath();
        try
        {
            var store = new FileKeyringStore(path);

            Task<string> first = Task.Run(async () => { await store.SaveAsync("first").ConfigureAwait(false); return "first"; });
            Task<string> second = Task.Run(async () => { await store.SaveAsync("second").ConfigureAwait(false); return "second"; });

            await Task.WhenAll(first, second);

            Assert.True(File.Exists(path));
            string final = await File.ReadAllTextAsync(path);
            Assert.True(final is "first" or "second", $"Final payload was neither writer's: '{final}'.");

            AssertNoStrayTempFiles(path);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task SerialWrites_LeaveOnlyTheTargetFile_NoStrayTempFiles()
    {
        // The documented production model — one writer, many readers. Exercises both the
        // FileNotFound → Move branch (first save) and the Replace branch (subsequent saves).
        string path = NewTempPath();
        try
        {
            var store = new FileKeyringStore(path);

            await store.SaveAsync("first");
            await store.SaveAsync("second");
            await store.SaveAsync("third");

            Assert.Equal("third", await File.ReadAllTextAsync(path));
            AssertNoStrayTempFiles(path);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task ConcurrentReaders_AlwaysSeeAValidPayload_WhileSingleWriterUpdates()
    {
        // One writer, many readers — the production model. Readers must always see *some*
        // valid payload (the file is never observed in a half-written state because the writer
        // uses atomic Replace).
        string path = NewTempPath();
        try
        {
            var store = new FileKeyringStore(path);
            await store.SaveAsync("seed"); // ensure the file exists before readers start

            using CancellationTokenSource cts = new();
            Task writer = Task.Run(async () =>
            {
                int i = 0;
                while (!cts.IsCancellationRequested)
                {
                    await store.SaveAsync($"value-{i++:D6}").ConfigureAwait(false);
                }
            });

            Task[] readers = Enumerable.Range(0, Environment.ProcessorCount).Select(_ => Task.Run(async () =>
            {
                for (int iter = 0; iter < 200; iter++)
                {
                    string? observed = await store.LoadAsync().ConfigureAwait(false);
                    Assert.NotNull(observed);
                    Assert.True(observed!.StartsWith("seed", StringComparison.Ordinal)
                                || observed.StartsWith("value-", StringComparison.Ordinal),
                        $"Reader observed unexpected payload: '{observed}'.");
                }
            })).ToArray();

            await Task.WhenAll(readers);
            cts.Cancel();
            try { await writer; } catch (OperationCanceledException) { /* expected */ }

            AssertNoStrayTempFiles(path);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static void AssertNoStrayTempFiles(string path)
    {
        string dir = System.IO.Path.GetDirectoryName(path) ?? Directory.GetCurrentDirectory();
        string nameStem = System.IO.Path.GetFileName(path);
        string[] strays = Directory.GetFiles(dir, $"{nameStem}.tmp-*");
        Assert.Empty(strays);
    }

    private static string NewTempPath()
        => System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"pqkm-conc-{Guid.NewGuid():N}.bin");
}
