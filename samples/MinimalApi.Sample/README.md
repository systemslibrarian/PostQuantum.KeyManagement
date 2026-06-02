# MinimalApi.Sample

A small ASP.NET Core minimal-API showing how to use
[`PostQuantum.KeyManagement`](../../src/PostQuantum.KeyManagement)'s built-in
`Microsoft.Extensions.DependencyInjection` integration to envelope-encrypt request payloads in a
realistic web service.

## What it demonstrates

- One-line registration of `IContentKeyProvider` via `AddPostQuantumKeyManagement`.
- A `KeyringPath` so the multi-KEK ring survives process restarts (via `FileKeyringStore`'s
  atomic-write semantics).
- A `POST /secrets` endpoint that creates a fresh DEK, encrypts the body with AES-GCM, and stores
  the ciphertext + nonce + tag + wrapped key.
- A `GET /secrets/{id}` endpoint that re-unwraps the DEK and decrypts the payload — proving that
  data wrapped under an older KEK still decrypts after rotation.
- A `POST /rotate` endpoint that rotates the active KEK. Old wrapped keys keep unwrapping; new
  secrets are wrapped under the new KEK.
- A `/health` endpoint backed by `KeyManagementHealthCheck`.

## Running

```bash
cd samples/MinimalApi.Sample
ASPNETCORE_ENVIRONMENT=Development dotnet run
```

The dev environment sets a placeholder passphrase in `appsettings.Development.json`. **Never** ship
a real passphrase in a checked-in config — wire it through a secret manager / environment variable.

## Try it

```bash
# Encrypt
curl -X POST http://localhost:5000/secrets \
  -H 'Content-Type: application/json' \
  -d '{"plaintext":"my secret data"}'

# → { "id": "ab12...", "keyId": "local-deadbeef" }

# Decrypt
curl http://localhost:5000/secrets/ab12...

# Rotate (in real apps gate this behind authentication)
curl -X POST http://localhost:5000/rotate \
  -H 'Content-Type: application/json' \
  -d '{"newPassphrase":"a stronger passphrase"}'

# Health
curl http://localhost:5000/health
```

After a rotation, GET-ing the original secret still works — the wrapped key from the first POST
references the old KEK, which the provider still holds in its ring.

---

*To God be the glory — 1 Corinthians 10:31.*
