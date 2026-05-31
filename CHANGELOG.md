# Changelog

All notable changes to `PostQuantum.KeyManagement` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the library uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0-preview.1] — 2026-05-31

### Added

- **New sibling package** `PostQuantum.KeyManagement.Extensions.DependencyInjection` —
  Microsoft.Extensions.DependencyInjection integration. Single-line registration
  (`AddPostQuantumKeyManagement`), options binding from `IConfiguration`, an `IKeyringStore`
  abstraction with a built-in atomic `FileKeyringStore`, and a `KeyManagementHealthCheck`. Targets
  net8.0/net9.0/net10.0; no SDK dependencies on the core's runtime path.
- **Three working samples** under `samples/`:
  - `MinimalApi.Sample` — ASP.NET Core minimal-API with envelope-encryption endpoints, rotation,
    and a `/health` check backed by `KeyManagementHealthCheck`.
  - `WorkerService.Sample` — a .NET worker service with a liveness probe and a scheduled rotation
    worker that persists the multi-KEK ring through `FileKeyringStore` on every rotation.
  - `EfCore.Sample` — per-row envelope encryption with EF Core + SQLite. Demonstrates lazy
    migration: KEK rotation does not invalidate existing rows.
- **`docs/deployment.md`** — production operational guide: passphrase storage, keyring backup /
  restore drill, rotation cadence, monitoring, container / Kubernetes notes, and the realities of
  multi-instance deployments.
- **`future.md`** — concrete path to cloud KMS providers (Azure Key Vault, AWS KMS),
  external cryptographic review, and `1.0`, with provisioning scripts and a definition of done for
  each.
- **`docs/threat-model.md`** — explicit attacker model, security invariants (I-1…I-10), and
  out-of-scope threats. The companion to `SECURITY.md`.
- **`docs/versioning.md`** — SemVer policy, wire-format compatibility policy, and the target-framework
  support matrix.
- **Per-KEK verifier in the keyring metadata.** Each KEK now carries a 16-byte HMAC-SHA256 tag over
  a fixed library label, keyed by the KEK itself. At import time `LocalContentKeyProvider.Import`
  recomputes the tag and rejects the supplied passphrase up front (with a clear
  `InvalidOperationException`) instead of failing later as an `AuthenticationTagMismatchException`
  at first unwrap. Closes KNOWN-GAPS #4 for v0.3+ tokens.
- **Keyring format version 2** — written by this release, with the verifier field. Version 1
  tokens produced by 0.2 are still decoded and imported for backward compatibility (without the
  import-time check; first-unwrap detection still applies).
- **Documented thread-safety contract on `LocalContentKeyProvider`.** All members are safe to call
  concurrently. Rotation, wrap, and unwrap serialise on a private lock so a rotation can no longer
  dispose a KEK that another thread is using. Closes KNOWN-GAPS #7.
- **`LocalKekOptions` presets** — `Interactive` (RFC 9106 §4 second recommendation), `Moderate`,
  `Sensitive` (RFC 9106 §4 first recommendation, 2 GiB), and `LowMemory` (OWASP minimum). The
  instance defaults match `Interactive`.

### Changed

- **`Rotate` now refuses to silently replace an existing KEK** with the same id. Passing a salt that
  collides with an in-ring KEK throws `InvalidOperationException`. The previous behaviour disposed
  the existing entry, which would lose the ability to unwrap any key already wrapped under it. The
  default `Rotate` overload (random salt) is unaffected; collisions there are astronomical.
- **Unwrap defensively rejects malformed blob lengths.** Local-provider unwrap now requires the
  payload after nonce+tag to equal 32 bytes (the content-key size) and throws
  `CryptographicException` otherwise, before invoking AES-GCM. Previously the cipher accepted any
  length and produced a same-sized buffer.

### Security

- **Token parsers hardened against malicious input.** `Internal/PortableEncoding` length checks now
  use overflow-safe subtraction (`length > data.Length - offset`) so an `int.MaxValue` length
  prefix can no longer bypass the bounds check. Every length-prefixed field is capped at 1 MiB by
  default, and `LocalKeyringMetadata.Decode` caps the KEK count at 1024, so a hostile token cannot
  force a giant allocation.

### Tests

- Added suites for: ciphertext / tag tamper detection, malformed token rejection, integer-overflow
  attempts, disposed-provider behaviour, verifier mismatch at import, v1 backward-compat decode,
  concurrent wrap/unwrap during rotation, `LocalKekOptions` presets, and the new content-key length
  defense. 42 tests, all green.

## [0.2.0-preview.1] — 2026

### Added

- First-class local keyring **export/import** (`ExportMetadata`, `LocalContentKeyProvider.Import`,
  `LocalKeyringMetadata`). Multi-KEK rotation now survives process restarts: the exported metadata
  is non-secret (salts + Argon2id parameters + active KEK id), and import re-derives every KEK from
  passphrases supplied through a `PassphraseResolver`.

## [0.1.0-preview.1]

### Added

- Initial preview: the `IContentKeyProvider` abstraction, the local Argon2id + AES-256-GCM KEK
  provider with in-process key rotation, and provider extensibility via `ContentKeyProvider`.

---

*To God be the glory — 1 Corinthians 10:31.*
