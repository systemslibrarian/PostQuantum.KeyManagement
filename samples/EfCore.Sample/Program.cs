// Demonstrates explicit envelope encryption of an EF Core entity column. SQLite is used as the
// store because the only thing we want this sample to depend on is the file system; switch the
// connection string to SQL Server / PostgreSQL / etc. without changing anything else.

using EfCore.Sample;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Extensions.DependencyInjection;
using PostQuantum.KeyManagement.Local;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

builder.Services.AddDbContext<NotesDbContext>(o => o.UseSqlite("Data Source=notes.db"));
builder.Services.AddPostQuantumKeyManagement(opts =>
{
    opts.Passphrase = "ef-core-sample-passphrase-replace-me-in-real-deployments";
    opts.WorkFactor = KekWorkFactor.LowMemory; // fast for the demo; do not copy into production
    opts.KeyringPath = "keyring.bin";
});
builder.Services.AddScoped<SecureNotesRepository>();

IHost host = builder.Build();

using (IServiceScope scope = host.Services.CreateScope())
{
    NotesDbContext db = scope.ServiceProvider.GetRequiredService<NotesDbContext>();
    await db.Database.EnsureCreatedAsync().ConfigureAwait(false);

    SecureNotesRepository notes = scope.ServiceProvider.GetRequiredService<SecureNotesRepository>();
    IContentKeyProvider keys = scope.ServiceProvider.GetRequiredService<IContentKeyProvider>();

    Console.WriteLine($"Active KEK at startup: {keys.ActiveKeyId}");

    // 1. Save an encrypted note.
    int id = await notes.CreateAsync("PSA", "Premature rotation is the root of all evil.").ConfigureAwait(false);
    Console.WriteLine($"Inserted note id={id}, wrapped under {keys.ActiveKeyId}.");

    // 2. Read it back through the repository (which unwraps + decrypts).
    var loaded = await notes.GetAsync(id).ConfigureAwait(false);
    Console.WriteLine($"Read back: \"{loaded?.Title}\" -> \"{loaded?.Body}\"");

    // 3. Inspect the raw row to prove the body never lived in the database in plaintext.
    SecureNote raw = await db.Notes.AsNoTracking().FirstAsync(n => n.Id == id).ConfigureAwait(false);
    Console.WriteLine($"Raw row body bytes (hex, first 32): {Convert.ToHexString(raw.Ciphertext.AsSpan(0, Math.Min(32, raw.Ciphertext.Length)))}");
    Console.WriteLine($"Raw row wrapped key: {raw.WrappedKey[..40]}...");

    // 4. Rotate the KEK, then read the same row again to prove rotation does not invalidate data.
    if (keys is LocalContentKeyProvider local)
    {
        string newActive = local.Rotate("a-stronger-passphrase-after-rotation");
        Console.WriteLine($"Rotated KEK -> {newActive}.");

        var afterRotation = await notes.GetAsync(id).ConfigureAwait(false);
        Console.WriteLine($"Read back after rotation: \"{afterRotation?.Title}\" -> \"{afterRotation?.Body}\"");
        Console.WriteLine($"Row's wrapped key still references the original KEK: {WrappedContentKey.Decode(raw.WrappedKey).KeyId}");
    }
}

Console.WriteLine("Done. notes.db + keyring.bin were created in the working directory; rerun to see persistence in action.");
