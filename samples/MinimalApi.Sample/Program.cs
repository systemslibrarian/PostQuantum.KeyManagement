// A minimal API showing how to use PostQuantum.KeyManagement.Extensions.DependencyInjection in a
// realistic ASP.NET Core app: register the provider once, persist the keyring across restarts,
// envelope-encrypt request payloads with rotatable wrapped keys, and decrypt them on read.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using PostQuantum.KeyManagement;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Bind passphrase + keyring path from configuration. In production this should come from a secret
// manager (Azure Key Vault, AWS Secrets Manager, environment variables) — never appsettings.json.
builder.Services.AddPostQuantumKeyManagement(options =>
{
    options.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? throw new InvalidOperationException("KeyManagement:Passphrase not configured");
    options.WorkFactor = KekWorkFactor.Interactive;
    options.KeyringPath = builder.Configuration["KeyManagement:KeyringPath"] ?? "keyring.bin";
});

builder.Services.AddHealthChecks().AddPostQuantumKeyManagement();

// Trivial in-memory secret store, just so this sample focuses on encryption and not on database
// plumbing. Real apps would persist the {ciphertext, nonce, tag, wrapped key} tuple to a database.
builder.Services.AddSingleton<SecretStore>();

WebApplication app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    name = "PostQuantum.KeyManagement minimal-api sample",
    endpoints = new[] { "POST /secrets", "GET /secrets/{id}", "POST /rotate", "GET /health" },
}));

app.MapHealthChecks("/health");

// POST a plaintext secret. The handler creates a fresh content key, encrypts the payload with
// AES-GCM, and persists the ciphertext alongside the wrapped key. The plaintext is never stored.
app.MapPost("/secrets", async (
    SecretRequest request,
    IContentKeyProvider keys,
    SecretStore store,
    CancellationToken cancellationToken) =>
{
    if (string.IsNullOrEmpty(request.Plaintext))
    {
        return Results.BadRequest(new { error = "Plaintext is required." });
    }

    byte[] plaintext = Encoding.UTF8.GetBytes(request.Plaintext);
    byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
    byte[] ciphertext = new byte[plaintext.Length];
    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

    using (ContentKey contentKey = await keys.CreateContentKeyAsync(cancellationToken))
    {
        using var aes = new AesGcm(contentKey.Key, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        string id = store.Save(new StoredSecret(
            Ciphertext: ciphertext,
            Nonce: nonce,
            Tag: tag,
            WrappedKey: contentKey.WrappedKey));

        return Results.Ok(new { id, keyId = contentKey.WrappedKey.KeyId });
    }
});

// GET retrieves and decrypts the secret. Demonstrates that a wrapped key persisted on day 1 still
// unwraps after rotations on day N — the data never has to be re-encrypted.
app.MapGet("/secrets/{id}", async (
    string id,
    IContentKeyProvider keys,
    SecretStore store,
    CancellationToken cancellationToken) =>
{
    StoredSecret? stored = store.Get(id);
    if (stored is null)
    {
        return Results.NotFound();
    }

    using ContentKey contentKey = await keys.UnwrapAsync(stored.WrappedKey, cancellationToken);
    byte[] plaintext = new byte[stored.Ciphertext.Length];
    using (var aes = new AesGcm(contentKey.Key, stored.Tag.Length))
    {
        aes.Decrypt(stored.Nonce, stored.Ciphertext, stored.Tag, plaintext);
    }

    return Results.Ok(new
    {
        id,
        plaintext = Encoding.UTF8.GetString(plaintext),
        wrappedUnderKeyId = stored.WrappedKey.KeyId,
        currentActiveKeyId = keys.ActiveKeyId,
    });
});

// Rotate the KEK. In a real deployment this would be a scheduled job or admin endpoint, gated
// behind authentication. Existing wrapped keys keep unwrapping under their original KEKs; new
// content keys are wrapped under the new active KEK.
app.MapPost("/rotate", (
    [Microsoft.AspNetCore.Mvc.FromBody] RotateRequest request,
    IContentKeyProvider keys) =>
{
    if (keys is not PostQuantum.KeyManagement.Local.LocalContentKeyProvider local)
    {
        return Results.Problem("This sample only knows how to rotate the local provider.");
    }

    string newKeyId = local.Rotate(request.NewPassphrase);
    return Results.Ok(new { activeKeyId = newKeyId });
});

app.Run();

internal sealed class SecretStore
{
    private readonly ConcurrentDictionary<string, StoredSecret> _byId = new(StringComparer.Ordinal);

    public string Save(StoredSecret secret)
    {
        string id = Guid.NewGuid().ToString("N");
        _byId[id] = secret;
        return id;
    }

    public StoredSecret? Get(string id) => _byId.TryGetValue(id, out StoredSecret? s) ? s : null;
}

internal sealed record StoredSecret(byte[] Ciphertext, byte[] Nonce, byte[] Tag, WrappedContentKey WrappedKey);

internal sealed record SecretRequest([property: JsonPropertyName("plaintext")] string Plaintext);

internal sealed record RotateRequest([property: JsonPropertyName("newPassphrase")] string NewPassphrase);
