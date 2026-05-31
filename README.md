# PostQuantum.KeyManagement

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4.svg)](#requirements)
[![Status](https://img.shields.io/badge/status-preview-orange.svg)](#project-status)

Clean, high-level **key management and rotation** for post-quantum-ready encryption in .NET.

`PostQuantum.KeyManagement` gives you a small, honest abstraction over the part of cryptography
that is easiest to get wrong: **managing the keys that protect your keys.** It implements the
*envelope encryption* pattern — short-lived random **content keys** (data-encryption keys, "DEKs")
that are wrapped by a long-lived **key-encryption key** ("KEK") — and makes the KEK pluggable so the
same code runs against a local passphrase today and a cloud HSM tomorrow.

It is the natural companion to [`PostQuantum.FileEncryption`](https://github.com/systemslibrarian),
[`PostQuantum.Jwt`](https://github.com/systemslibrarian), and the other `PostQuantum.*` libraries.

> ⚠️ **Preview (`0.3.0-preview.1`).** The API surface is small and may still change before `1.0`.
> Please read [KNOWN-GAPS.md](KNOWN-GAPS.md) before relying on it — it is deliberately blunt about
> what this library does and does **not** yet do. See [CHANGELOG.md](CHANGELOG.md) for what landed
> in each release.

---

## Why this exists

Most encryption bugs are not broken ciphers — they are mishandled keys: keys logged by accident,
keys that can never be rotated, keys hard-coded next to the data they protect. This library narrows
the surface you have to reason about to three things:

- **Where does a fresh content key come from?** → `CreateContentKeyAsync`
- **How do I get it back later?** → `UnwrapAsync`
- **How do I rotate the key that protects everything?** → `RewrapAsync` / `Rotate`

Everything else — random key generation, zeroing key material, authenticated wrapping — is handled
for you and is identical across providers.

## Requirements

- .NET 8.0, .NET 9.0, or .NET 10.0

## Installation

```bash
dotnet add package PostQuantum.KeyManagement --prerelease
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

    wrapped = key.WrappedKey;                 // safe to store next to the ciphertext
    string token = wrapped.Encode();          // ...or as a compact URL-safe string
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

## Key rotation

Rotation never re-encrypts your data. It re-wraps the content key under a new KEK; the content key
itself — and therefore your ciphertext — is untouched.

```csharp
using var keys = LocalContentKeyProvider.Create("old passphrase");
WrappedContentKey wrapped = (await keys.CreateContentKeyAsync()).WrappedKey;

// Rotate in a new KEK. Old keys still unwrap; new content keys use the new KEK.
string newKeyId = keys.Rotate("new, stronger passphrase");

// Migrate an existing key onto the new KEK at your leisure.
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

A wrong passphrase is caught at import (constant-time HMAC-SHA256 verifier) and surfaces as
`InvalidOperationException` with the offending key id — not as a later
`AuthenticationTagMismatchException` at first unwrap.

## Tuning the KEK work factor

`LocalKekOptions` ships with presets aligned to RFC 9106 and OWASP:

| Preset       | Memory | Iterations | Parallelism | When to use                                   |
| ------------ | ------ | ---------- | ----------- | --------------------------------------------- |
| `Interactive`| 64 MiB | 3          | 4           | server-side default — RFC 9106 §4 "second"    |
| `Moderate`   | 256 MiB| 4          | 4           | background jobs, admin operations             |
| `Sensitive`  | 2 GiB  | 1          | 4           | long-lived master KEKs — RFC 9106 §4 "first"  |
| `LowMemory`  | 19 MiB | 2          | 1           | constrained hosts (CI, edge) — OWASP minimum  |

```csharp
using var keys = LocalContentKeyProvider.Create("strong passphrase", LocalKekOptions.Sensitive);
```

The instance defaults match `Interactive`. Whatever you pick gets recorded per-KEK in the exported
metadata, so future rebuilds reproduce the exact same KEK.

## Extending to a cloud KMS

Cloud providers (Azure Key Vault, AWS KMS, Google Cloud KMS, a PKCS#11 HSM, …) are **not bundled** in
`0.1` — but the extension point is deliberately tiny. Derive from `ContentKeyProvider` and implement
only how a content key is wrapped and unwrapped; the random key generation, rotation flow, and memory
hygiene come from the base class:

```csharp
public sealed class AzureKeyVaultContentKeyProvider : ContentKeyProvider
{
    public override string ProviderId => "azure-key-vault";
    public override string ActiveKeyId => _currentKeyVersionId;
    protected override string WrapAlgorithm => "RSA-OAEP-256"; // whatever the vault performs

    protected override async ValueTask<byte[]> WrapKeyAsync(
        string keyId, ReadOnlyMemory<byte> contentKey, CancellationToken ct)
        => (await _cryptoClient.WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, contentKey.ToArray(), ct)).EncryptedKey;

    protected override async ValueTask<byte[]> UnwrapKeyAsync(
        WrappedContentKey wrappedKey, CancellationToken ct)
        => (await _cryptoClient.UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, wrappedKey.Ciphertext, ct)).Key;
}
```

See [`docs/extending-providers.md`](docs/extending-providers.md) for the full walkthrough.

## Security posture

- **Content keys** are 256-bit and drawn from `RandomNumberGenerator`.
- **Wrapping** uses **AES-256-GCM** (authenticated): tampering with a wrapped key is detected, never
  silently decrypted to garbage.
- **Local KEK derivation** uses **Argon2id** with OWASP-interactive defaults (64&#160;MiB / 3 iterations /
  parallelism 4), tunable via `LocalKekOptions`.
- **Memory hygiene:** plaintext key material lives in `ContentKey`, which zeroes its buffer on
  `Dispose`. Always wrap content keys in `using`.
- **Quantum stance:** the symmetric layer here (AES-256, Argon2id) is already considered
  quantum-resistant by key size. This library does **not yet** add a post-quantum *asymmetric* KEM
  (e.g. ML-KEM) for key wrapping — that, and hybrid wrapping, are tracked in
  [KNOWN-GAPS.md](KNOWN-GAPS.md). We would rather under-claim than overstate.
- **Thread-safety:** `LocalContentKeyProvider` is safe for concurrent use. Rotation, wrap, and
  unwrap serialise on a private lock so a rotating thread cannot dispose a KEK that another thread
  is using.
- **Defensive parsing:** every token decoder uses overflow-safe length arithmetic and caps fields
  at 1 MiB; the keyring decoder caps the number of KEKs. A malicious token cannot trigger huge
  allocations or out-of-bounds reads.

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## Project status

`0.3.0-preview.1` — production-hardened preview. Adds an HMAC-SHA256 per-KEK verifier (wrong
passphrases fail at import, not at first unwrap), full thread-safety on `LocalContentKeyProvider`,
overflow-safe token parsing with allocation caps, `LocalKekOptions` presets aligned to RFC 9106 /
OWASP, and a defensive content-key length check on unwrap. See [CHANGELOG.md](CHANGELOG.md) for the
full list; cloud providers and a post-quantum asymmetric wrapping layer are next on the roadmap in
[KNOWN-GAPS.md](KNOWN-GAPS.md).

## Building from source

```bash
dotnet build      # builds net8.0, net9.0, net10.0
dotnet test       # runs the round-trip and rotation suites
dotnet pack -c Release
```

## License

[MIT](LICENSE) © 2026 Paul Clark.

---

*To God be the glory — 1 Corinthians 10:31.*
