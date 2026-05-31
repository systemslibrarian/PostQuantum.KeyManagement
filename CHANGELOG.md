# Changelog

All notable changes to `PostQuantum.KeyManagement` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the library uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0-preview.1] — 2026-05-31

This release turns the hardened 0.3 core into a production-shaped preview. Adds the DI
integration package as a peer NuGet package, three end-to-end samples, full documentation set
(threat model, versioning policy, deployment guide), and small API refinements that elevate
day-to-day usability.

### Added

- **Sibling package** `PostQuantum.KeyManagement.Extensions.DependencyInjection` — the idiomatic
  way to wire the provider into any `Microsoft.Extensions.DependencyInjection` host:
  - `AddPostQuantumKeyManagement(options => ...)` registers a singleton `IContentKeyProvider`.
    Idempotent — calling it twice does not double-register.
  - `KeyManagementOptions` with a `KekWorkFactor` enum mapping to the static `LocalKekOptions`
    presets. Bindable from `IConfiguration`.
  - `IKeyringStore` abstraction with a built-in `FileKeyringStore` (atomic temp+rename writes,
    so a crashed write cannot leave a half-written file).
  - `KeyManagementHealthCheck` that runs a real wrap → unwrap round-trip, surfaced via
    `services.AddHealthChecks().AddPostQuantumKeyManagement()`.
- **Three end-to-end samples** in `samples/`:
  - `MinimalApi.Sample` — ASP.NET Core minimal-API with envelope-encryption endpoints, rotation,
    and a `/health` check.
  - `WorkerService.Sample` — a .NET worker service with a liveness probe and a scheduled
    rotation worker that persists the keyring on every rotation.
  - `EfCore.Sample` — per-row envelope encryption with EF Core + SQLite. Demonstrates lazy
    migration: KEK rotation does not invalidate existing rows.
- **`TryDecode` overloads** on `WrappedContentKey` and `LocalKeyringMetadata` for exception-free
  parsing of untrusted input.
- **Boundary validation**: empty passphrases are rejected with a clear `ArgumentException` at
  the library boundary, before any cryptographic work runs.
- **Documentation set**:
  - `docs/threat-model.md` — attacker model, ten numbered security invariants, out-of-scope
    threats, and "what is not a vulnerability."
  - `docs/versioning.md` — SemVer policy, wire-format versioning matrix, API surface
    guarantees, TFM support matrix.
  - `docs/deployment.md` — production operational checklist: passphrase storage, keyring
    backup, rotation cadence, monitoring, multi-instance deployments, disaster recovery.
- **`future.md`** — concrete plan to ship Azure Key Vault and AWS KMS providers, commission an
  external review, and cut `1.0`, with provisioning scripts and definition-of-done for each.

### Changed

- **NuGet metadata polish.** Both packages now carry stronger `Description`, `Title`,
  `PackageTags`, and `PackageReleaseNotes`; the core declares `<IsAotCompatible>true</IsAotCompatible>`;
  both opt in to `<EnablePackageValidation>` and `<NeutralLanguage>en-US</NeutralLanguage>`.
- **README** rewritten to lead with concrete value, a 60-second demo, a local-vs-cloud table, and
  an opinionated key-rotation-best-practices checklist; the `PostQuantum.*` integration sketches
  now cover both `FileEncryption` and `Jwt`.
- **Safe `ToString()`** on the records that carry byte arrays (`WrappedContentKey`,
  `LocalKekMetadata`, `LocalKeyringMetadata`). The default record-generated output would emit
  `"System.Byte[]"` for ciphertext, salt, and verifier; the overrides render `<NN bytes>` instead,
  making the records safe to include in log lines.
- **`FileKeyringStore` is now race-free on Windows.** The atomic-swap helper retries `File.Replace`
  on Windows-specific `IOException` from concurrent readers (POSIX `rename(2)` is unaffected) with
  a bounded backoff. Combined with the existing TOCTOU handling, the single-writer +
  many-readers production model is now exercised by an integration test.
- **`TryDecode` overloads** are annotated with `[NotNullWhen(true)]` for cleaner nullable analysis
  at call sites.

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
