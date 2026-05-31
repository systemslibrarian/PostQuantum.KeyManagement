# PostQuantum.KeyManagement

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4.svg)](#requirements)
[![Status](https://img.shields.io/badge/status-preview-orange.svg)](#project-status)
[![NuGet](https://img.shields.io/badge/NuGet-PostQuantum.KeyManagement-004880.svg)](https://www.nuget.org/packages/PostQuantum.KeyManagement)

> **Clean, high-level key management and rotation for post-quantum-ready encryption in .NET.**
> The default safe answer to: *"How do I encrypt data with rotatable keys without building my own
> dangerous key-management layer?"*

`PostQuantum.KeyManagement` is the small, honest abstraction over the part of cryptography that is
easiest to get wrong: **managing the keys that protect your keys.** It implements the
*envelope encryption* pattern — short-lived random **content keys** (data-encryption keys, "DEKs")
wrapped by long-lived **key-encryption keys** ("KEKs") — and makes the KEK pluggable so the same
code runs against a local passphrase today and a cloud HSM tomorrow.

It is the natural companion to [`PostQuantum.FileEncryption`](https://github.com/systemslibrarian),
[`PostQuantum.Jwt`](https://github.com/systemslibrarian), and the rest of the `PostQuantum.*` family.

> ⚠️ **Preview (`0.4.0-preview.1`).** The API surface is small and may still change before `1.0`.
> Read [KNOWN-GAPS.md](KNOWN-GAPS.md) before relying on it — it is deliberately blunt about what
> this library does and does **not** yet do. The full release notes are in
> [CHANGELOG.md](CHANGELOG.md); the path to `1.0`, cloud KMS providers, and external review is
> mapped out in [future.md](future.md).

---

## Why it exists

Most encryption bugs are not broken ciphers — they are mishandled keys: keys logged by accident,
keys that can never be rotated, keys hard-coded next to the data they protect. This library narrows
the surface you have to reason about to three things:

| Question                                            | Answer                       |
| --------------------------------------------------- | ---------------------------- |
| Where does a fresh content key come from?           | `CreateContentKeyAsync()`    |
| How do I get it back later?                         | `UnwrapAsync(wrappedKey)`    |
| How do I rotate the key that protects everything?   | `Rotate(...)` + `RewrapAsync(...)` |

Everything else — random key generation, zeroing key material, authenticated wrapping, thread
safety, hostile-input rejection — is handled for you and is identical across providers.

## Try the demo in 60 seconds

Three working samples ship in [`samples/`](samples):

```bash
# Minimal API: HTTP endpoints that envelope-encrypt request bodies and rotate KEKs
cd samples/MinimalApi.Sample && ASPNETCORE_ENVIRONMENT=Development dotnet run

# Worker Service: liveness probe + scheduled rotation + durable keyring
cd samples/WorkerService.Sample && DOTNET_ENVIRONMENT=Development dotnet run

# EF Core: per-row envelope encryption with SQLite that survives a KEK rotation
cd samples/EfCore.Sample && dotnet run
```

Each sample has its own README explaining what it demonstrates and how to adapt it to production.

## Requirements

- .NET **8.0**, **9.0**, or **10.0** (multi-targeted, deterministic, SourceLink, symbol packages).

## Installation

```bash
# Core library
dotnet add package PostQuantum.KeyManagement --prerelease

# Microsoft.Extensions.DependencyInjection integration (optional, recommended for ASP.NET Core / hosts)
dotnet add package PostQuantum.KeyManagement.Extensions.DependencyInjection --prerelease
```

## Quick start

```csharp
using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;

// 1. Create a provider. The local provider derives its KEK from a passphrase with Argon2id.
using var keys = LocalContentKeyProvider.Create("a strong, high-entropy passphrase");

// Persist this salt (it is NOT secret) so you can re-derive the same KEK later.
byte[] salt = keys.ActiveSalt.ToArray();

// 2. Mint a fresh content key, encrypt your data with it, and store the *wrapped* key.
WrappedContentKey wrapped;
using (ContentKey key = await keys.CreateContentKeyAsync())
{
    // key.Key is a 256-bit DEK — use it with AES-GCM, ChaCha20-Poly1305, your file format, etc.
    EncryptMyData(key.Key);

    wrapped = key.WrappedKey;            // safe to store next to the ciphertext
    string token = wrapped.Encode();     // ...or as a compact URL-safe string
}

// 3. Later — recover the content key from its wrapped form.
using (ContentKey key = await keys.UnwrapAsync(wrapped))
{
    DecryptMyData(key.Key);
}
```

Re-deriving the same KEK in a different process:

```csharp
using var keys = LocalContentKeyProvider.Create("a strong, high-entropy passphrase", salt);
using ContentKey key = await keys.UnwrapAsync(wrapped); // works — same KEK
```

For untrusted input (network payloads, user-supplied tokens), use the exception-free overload:

```csharp
if (WrappedContentKey.TryDecode(token, out var wrapped) && wrapped is not null)
{
    using ContentKey key = await keys.UnwrapAsync(wrapped);
    // ...
}
```

## Key rotation

Rotation **never re-encrypts your data.** It re-wraps the content key under a new KEK; the content
key itself — and therefore your ciphertext — is untouched.

```csharp
using var keys = LocalContentKeyProvider.Create("old passphrase");
WrappedContentKey wrapped = (await keys.CreateContentKeyAsync()).WrappedKey;

// Rotate in a new KEK. Old keys still unwrap; new content keys use the new KEK.
string newKeyId = keys.Rotate("new, stronger passphrase");

// Migrate an existing wrapped key onto the new KEK at your leisure.
WrappedContentKey migrated = await keys.RewrapAsync(wrapped);
// migrated.KeyId == newKeyId, but it still unwraps to the exact same content key.
```

## Persisting the keyring across restarts

After one or more rotations the provider holds several KEKs. Export the ring's **non-secret**
structure (salts + Argon2id parameters + a per-KEK integrity verifier + which KEK is active) and
rebuild it later by supplying the passphrases — the export never contains key material or
passphrases.

```csharp
// Before shutdown: persist the keyring structure (safe to store next to your data).
string keyring = keys.ExportMetadata().Encode();

// After restart: rebuild, providing the passphrase for each KEK by id.
LocalKeyringMetadata metadata = LocalKeyringMetadata.Decode(keyring);
PassphraseResolver passphrases = keyId => LookUpPassphraseFor(keyId);

using var keys = LocalContentKeyProvider.Import(metadata, passphrases);
// Every KEK is back: keys wrapped under rotated-out KEKs still unwrap, and the active KEK is restored.
```

A wrong passphrase is caught at **import** time (constant-time HMAC-SHA256 verifier) with a clear
`InvalidOperationException` naming the offending key id — not as a delayed
`AuthenticationTagMismatchException` at first unwrap.

## Tuning the KEK work factor

`LocalKekOptions` ships with presets aligned to RFC 9106 and OWASP:

| Preset          | Memory  | Iterations | Parallelism | When to use                                   |
| --------------- | ------- | ---------- | ----------- | --------------------------------------------- |
| `Interactive`   | 64 MiB  | 3          | 4           | server-side default — RFC 9106 §4 "second"    |
| `Moderate`      | 256 MiB | 4          | 4           | background jobs, admin operations             |
| `Sensitive`     | 2 GiB   | 1          | 4           | long-lived master KEKs — RFC 9106 §4 "first"  |
| `LowMemory`     | 19 MiB  | 2          | 1           | constrained hosts (CI, edge) — OWASP minimum  |

```csharp
using var keys = LocalContentKeyProvider.Create("strong passphrase", LocalKekOptions.Sensitive);
```

The instance defaults match `Interactive`. Whatever you pick gets recorded per-KEK in the exported
metadata, so future rebuilds reproduce the exact same KEK.

## ASP.NET Core / host integration

The sibling package
[`PostQuantum.KeyManagement.Extensions.DependencyInjection`](src/PostQuantum.KeyManagement.Extensions.DependencyInjection)
wires the provider into any `Microsoft.Extensions.DependencyInjection` host (ASP.NET Core, worker
services, Blazor) in one line, persists the keyring via an atomic file store, and exposes a
real-round-trip health check.

```csharp
builder.Services.AddPostQuantumKeyManagement(options =>
{
    options.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? throw new InvalidOperationException("Missing passphrase");
    options.WorkFactor = KekWorkFactor.Interactive;
    options.KeyringPath = "keyring.bin";   // optional; survives restarts via FileKeyringStore
});

builder.Services.AddHealthChecks().AddPostQuantumKeyManagement();

// Anywhere in the app:
public sealed class SecretsService(IContentKeyProvider keys) { /* ... */ }
```

The samples table:

| Sample                                                     | What it shows                                                                 |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [`MinimalApi.Sample`](samples/MinimalApi.Sample)           | ASP.NET Core minimal-API with POST/GET/rotate endpoints + `/health`.          |
| [`WorkerService.Sample`](samples/WorkerService.Sample)     | A worker service with a liveness probe and a scheduled rotation worker that persists the keyring on every rotation. |
| [`EfCore.Sample`](samples/EfCore.Sample)                   | Per-row envelope encryption with EF Core + SQLite. Demonstrates that a KEK rotation does **not** invalidate existing rows. |

## Integration with the rest of the `PostQuantum.*` family

The DEK that `CreateContentKeyAsync` returns is just a 256-bit symmetric key — it composes with any
authenticated cipher. The shape with `PostQuantum.FileEncryption` looks like this (sketch — adjust
to the actual `FileEncryption` API):

```csharp
using var keys = LocalContentKeyProvider.Create(passphrase);

// Encrypt a file: mint a DEK, hand it to FileEncryption, persist the wrapped key.
WrappedContentKey wrapped;
using (ContentKey dek = await keys.CreateContentKeyAsync())
{
    await PostQuantumFile.EncryptAsync(
        input: "secret.docx",
        output: "secret.docx.enc",
        key: dek.Key);          // ReadOnlySpan<byte> — pass straight through

    wrapped = dek.WrappedKey;
}
File.WriteAllText("secret.docx.enc.key", wrapped.Encode());  // non-secret, safe to store

// Decrypt later: load the wrapped key, unwrap, decrypt.
WrappedContentKey w = WrappedContentKey.Decode(File.ReadAllText("secret.docx.enc.key"));
using (ContentKey dek = await keys.UnwrapAsync(w))
{
    await PostQuantumFile.DecryptAsync(
        input: "secret.docx.enc",
        output: "secret.docx",
        key: dek.Key);
}
```

The same shape applies to `PostQuantum.Jwt` (use the DEK as the JWT signing/encryption key), to
column-level encryption in EF Core (see `samples/EfCore.Sample`), and to any other library that
takes a symmetric key as `ReadOnlySpan<byte>`.

## Local vs cloud KMS

| Concern                  | Local provider                                       | Cloud KMS provider (when shipped)                   |
| ------------------------ | ---------------------------------------------------- | --------------------------------------------------- |
| Where the KEK lives      | Derived in-process from a passphrase via Argon2id    | In the cloud HSM; never leaves the service          |
| Wrap / unwrap latency    | ~microseconds (AES-GCM in-process)                   | One network round-trip per call (~ms)               |
| Cost                     | Free                                                 | Per-call charges                                    |
| Offline / air-gapped     | Yes                                                  | No                                                  |
| Audit trail              | Whatever you log                                     | Cloud provider's audit log                          |
| Best for                 | Single-tenant apps, edge, dev/test, file vaults      | Multi-tenant SaaS, compliance regimes, fleet scale  |

The same `IContentKeyProvider` interface fronts both. Switching from local to cloud is changing one
registration line — no application logic moves. Cloud providers (Azure Key Vault, AWS KMS, GCP
KMS) are tracked in [`future.md`](future.md); the extension point is documented in
[`docs/extending-providers.md`](docs/extending-providers.md).

## Security posture

- **Content keys** are 256-bit and drawn from `RandomNumberGenerator`.
- **Wrapping** uses **AES-256-GCM** (authenticated): tampering with a wrapped key is detected, never
  silently decrypted to garbage.
- **Local KEK derivation** uses **Argon2id** with presets aligned to RFC 9106 §4 and OWASP, tunable
  via `LocalKekOptions`.
- **Memory hygiene:** plaintext key material lives in `ContentKey`, which zeroes its buffer on
  `Dispose`. Always wrap content keys in `using`.
- **Quantum stance:** the symmetric layer here (AES-256, Argon2id) is already considered
  quantum-resistant by key size. This library does **not yet** add a post-quantum *asymmetric* KEM
  (e.g. ML-KEM) for key wrapping — that, and hybrid wrapping, are tracked in
  [KNOWN-GAPS.md](KNOWN-GAPS.md). We would rather under-claim than overstate.
- **Thread-safety:** `LocalContentKeyProvider` is safe for concurrent use. Rotation, wrap, and
  unwrap serialise on a private lock so a rotating thread cannot dispose a KEK that another thread
  is using.
- **Hostile-input resistance:** every token decoder uses overflow-safe length arithmetic and caps
  fields at 1 MiB; the keyring decoder caps the number of KEKs. A malicious token cannot trigger
  huge allocations or out-of-bounds reads. `TryDecode` overloads exist for inputs from untrusted
  sources.
- **Boundary validation:** empty passphrases are rejected with a clear `ArgumentException` at the
  library boundary, before any cryptographic work runs.

| Document                                            | What it tells you                                  |
| --------------------------------------------------- | -------------------------------------------------- |
| [`docs/threat-model.md`](docs/threat-model.md)      | Attacker model + 10 numbered security invariants   |
| [`docs/versioning.md`](docs/versioning.md)          | SemVer + wire-format compatibility commitments     |
| [`docs/deployment.md`](docs/deployment.md)          | Production operational checklist                   |
| [`docs/extending-providers.md`](docs/extending-providers.md) | How to add a cloud KMS provider           |
| [`KNOWN-GAPS.md`](KNOWN-GAPS.md)                    | What the library deliberately does NOT do yet      |
| [`future.md`](future.md)                            | Concrete plan to ship cloud providers and reach 1.0|

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Project status

`0.4.0-preview.1` — the preview is now production-shaped: a hardened core (HMAC-SHA256 verifier,
thread-safety, hostile-input rejection), a clean DI integration package with atomic keyring
persistence and a health check, three end-to-end samples, and a complete documentation set
(threat model, versioning policy, deployment guide). Cloud KMS providers, external review, and
`1.0` are next — the concrete plan is in [`future.md`](future.md).

## Building from source

```bash
dotnet build      # builds net8.0, net9.0, net10.0
dotnet test       # 74 tests across the core and DI packages
dotnet pack -c Release
```

## License

[MIT](LICENSE) © 2026 Paul Clark.

---

*To God be the glory — 1 Corinthians 10:31.*
