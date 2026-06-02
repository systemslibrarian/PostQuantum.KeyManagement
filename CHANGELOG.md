# Changelog

All notable changes to `PostQuantum.KeyManagement` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the library uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0-preview.2] — 2026-06-01

A hardening + honesty pass on top of `0.4.0-preview.1`. Backward-compatible: v1 and v2 keyrings
still decode and import. No crypto-logic changes — AES-GCM wrap, Argon2id parameters, and memory
zeroing are byte-for-byte identical to preview.1.

### Changed

- **Wrong-passphrase verifier widened from 16 to 32 bytes** (full HMAC-SHA256 output) so the
  import-time canary matches the library's 256-bit posture. Keyring metadata format bumped from
  **v2 → v3**. v1 tokens (no verifier, written by `0.2` and earlier) and v2 tokens (16-byte
  truncated verifier, written by `0.3` / `0.4-preview.1`) **still decode and import correctly**:
  the v3 reader compares whatever width the persisted token carries against the matching prefix of
  the recomputed 32-byte verifier in constant time (`CryptographicOperations.FixedTimeEquals`),
  so v2 keyrings continue to detect wrong passphrases at import. The verifier label is held
  stable, so the v3 verifier is bit-for-bit the prefix-extension of the v2 verifier.
- **README opening and `## Security posture` section rewritten** so the *very first* thing a
  reader learns is the honest scope of the "PostQuantum" claim: today's only post-quantum
  property is **symmetric-by-key-size** (AES-256-GCM + Argon2id, ~128-bit post-quantum strength
  under Grover). **No asymmetric PQ KEM ships in this release** — no ML-KEM, no X-Wing, no
  hybrid wrap. Every PQ mention in the posture section now links to
  [`KNOWN-GAPS.md` §1](KNOWN-GAPS.md#1-post-quantum-is-currently-a-symmetric-only-claim).
- **KEK-id collision documentation made honest.** Replaced the overstated "astronomical" wording
  in `KNOWN-GAPS.md` §7 and `README` with the actual figures: KEK id is a 48-bit truncation of
  SHA-256(salt); the birthday bound is ≈ 2²⁴; at the enforced `MaxKekCount = 1024` cap the
  worst-case accidental-collision probability is on the order of 2⁻²⁹ (≈ 1 in 540 million); at
  typical operational counts (single digits to ~100) it is 2⁻³⁶ or smaller. Operationally
  negligible — but not cryptographically astronomical. Behaviour is unchanged: `Rotate` refuses
  to clobber an existing KEK id, and Import's salt-id consistency check detects mismatches.

### Added

- **`SECURITY.md` — "Recommended Argon2id profile in production"**, a new section that pins
  `Moderate` (256 MiB / 4 iterations / parallelism 4) as the production floor against an
  attacker who has obtained the keyring metadata and is mounting an **offline GPU/ASIC-accelerated
  passphrase guess**. `Sensitive` (2 GiB) for long-lived master KEKs. `Interactive` (64 MiB)
  only when latency budget is the binding constraint. `LowMemory` (19 MiB) is **not** a general
  production setting. Linked from the README's "Security posture" section and from
  `docs/deployment.md` §4 as authoritative.
- **`Argon2idKatTests`** — a pinned Known-Answer Test suite:
  - `Rfc9106_AppendixA3_Argon2id_KnownAnswer` anchors the underlying Argon2id implementation to
    the **RFC 9106 §A.3 published reference vector** (password 32×0x01, salt 16×0x02, secret
    8×0x03, AD 12×0x04, t=3, m=32 KiB, p=4, tag length 32 — expected
    `0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659`).
  - `LocalProvider_PinnedKeyId_FromPinnedSalt` pins the KeyId derivation
    (`"local-" + hex(SHA-256(salt)[0..6])`) for a known salt.
  - `LocalProvider_PinnedVerifier_FromPinnedInputs` pins the 32-byte HMAC-SHA256 verifier for
    chosen `(passphrase, salt, options)` inputs, with in-fixture determinism and cross-process
    reproducibility cross-checks before the value was baked.
  - `Rotate_RejectsExplicitDuplicateSalt` exercises the rotation-collision rejection path.
- **`VerifierTests.Import_FromV2Token_With16ByteVerifier_StillImports`** — a regression test
  that hand-crafts a v2 token (16-byte truncated verifier) into the wire format, decodes it, and
  proves both branches of the new prefix-compare path: correct passphrase imports cleanly,
  wrong passphrase is rejected up front with `"Verifier mismatch"`.

### Documentation

- `KNOWN-GAPS.md` §1 cross-links the README's new scope note. §4 documents the actual KeyId
  truncation length and the collision-rejection behaviour explicitly. §7 replaces the
  "astronomical" claim with the honest birthday bound and refers back to §4 for the full treatment.
- `docs/deployment.md` §4 now defers to `SECURITY.md` as authoritative for the recommended
  production Argon2id profile.
- `LocalKekMetadata.Verifier` and `LocalKeyringMetadata` XML docs describe the v1 / v2 / v3
  width matrix and the prefix-compare semantics explicitly.

## [0.4.0-preview.1] — 2026-05-31

The first production-shaped preview. **One package** now contains the hardened core, the
`Microsoft.Extensions.DependencyInjection` integration (registration extensions, `IKeyringStore`
+ atomic Windows-aware `FileKeyringStore`, `KeyManagementHealthCheck`), three end-to-end samples,
and a complete documentation set (threat model, versioning policy, deployment guide). Future cloud
KMS providers (Azure Key Vault, AWS KMS, Google Cloud KMS) ship as separate packages so they can
carry cloud SDK dependencies without bloating the core.

### Added

- **`Microsoft.Extensions.DependencyInjection` integration**, in the same single package as the
  core (no second `using`, no second NuGet install). The extension methods live in the
  `Microsoft.Extensions.DependencyInjection` namespace by convention, so they appear automatically
  in any ASP.NET Core `Program.cs`:
  - `AddPostQuantumKeyManagement(options => ...)` registers a singleton `IContentKeyProvider`.
    Idempotent — `TryAddSingleton`-based, calling it twice does not double-register.
  - `KeyManagementOptions` with a `KekWorkFactor` enum mapping to the static `LocalKekOptions`
    presets. Bindable from `IConfiguration`.
  - `IKeyringStore` abstraction with a built-in atomic `FileKeyringStore`. Windows-aware:
    readers open with `FileShare.ReadWrite | FileShare.Delete` and retry transient
    `FileNotFoundException` / `IOException` from a writer's mid-`Replace` gap, so the single-
    writer + many-readers model is race-free.
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
