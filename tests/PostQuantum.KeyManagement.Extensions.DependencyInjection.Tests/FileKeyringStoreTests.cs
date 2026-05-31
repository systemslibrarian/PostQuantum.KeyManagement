using PostQuantum.KeyManagement.Extensions.DependencyInjection;
using Xunit;

namespace PostQuantum.KeyManagement.Extensions.DependencyInjection.Tests;

public sealed class FileKeyringStoreTests
{
    [Fact]
    public async Task LoadReturnsNullWhenFileMissing()
    {
        string path = NewTempPath();
        var store = new FileKeyringStore(path);

        Assert.Null(await store.LoadAsync());
    }

    [Fact]
    public async Task SaveThenLoad_RoundTripsExactly()
    {
        string path = NewTempPath();
        try
        {
            var store = new FileKeyringStore(path);
            await store.SaveAsync("hello-world-token");

            Assert.Equal("hello-world-token", await store.LoadAsync());
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
    public async Task Save_OverwritesPreviousContents()
    {
        string path = NewTempPath();
        try
        {
            var store = new FileKeyringStore(path);
            await store.SaveAsync("first");
            await store.SaveAsync("second");

            Assert.Equal("second", await store.LoadAsync());
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
    public async Task Save_DoesNotLeaveTempFilesOnSuccess()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"pqkm-store-{Guid.NewGuid():N}");
        string path = Path.Combine(dir, "keyring.bin");
        try
        {
            var store = new FileKeyringStore(path);
            await store.SaveAsync("payload");

            // The atomic-write helper writes to a *.tmp-<guid> sibling, then renames. None of those
            // siblings should be visible after a successful save.
            string[] tempFiles = Directory.GetFiles(dir, "*.tmp-*");
            Assert.Empty(tempFiles);
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public void Constructor_RejectsEmptyPath()
    {
        Assert.Throws<ArgumentException>(() => new FileKeyringStore(""));
        Assert.Throws<ArgumentException>(() => new FileKeyringStore("  "));
    }

    private static string NewTempPath()
        => Path.Combine(Path.GetTempPath(), $"pqkm-{Guid.NewGuid():N}.bin");
}
