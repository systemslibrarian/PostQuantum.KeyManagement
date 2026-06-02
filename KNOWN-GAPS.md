# Known Gaps

This file is the honest counterpart to the README. It lists what `PostQuantum.KeyManagement` does
**not** do yet, what is deliberately out of scope, and where the design has sharp edges. If
something here surprises you *after* you shipped, that is a documentation bug — please open an
issue.

Status as of **`0.4.0-preview.2`**.

For the precise threat model and the security invariants we DO commit to, see
[`docs/threat-model.md`](docs/threat-model.md). For the production operational checklist, see
[`docs/deployment.md`](docs/deployment.md). For the concrete plan to close the cloud-provider and
audit gaps below, see [`future.md`](future.md).

## 1. "Post-quantum" is currently a symmetric-only claim

- The cryptography that ships here is **AES-256-GCM** (wrapping), **Argon2id** (passphrase
  stretching), and **HMAC-SHA256** (the keyring verifier). All three are considered
  quantum-resistant *by key size* — Grover's algorithm only halves the effective security of a
  symmetric primitive, so AES-256 retains ~128-bit post-quantum strength.
- **There is no post-quantum asymmetric primitive here yet.** No ML-KEM (Kyber), no X-Wing, no
  hybrid KEM, no PQ signatures. The library name reflects the *family* it belongs to and the
  direction of travel, **not** a claim that the current release performs PQ key exchange.
- The asymmetric story matters most for cloud/HSM wrapping (where a KEK wraps a DEK with RSA/ECC)
  and for cross-party key exchange. That is exactly where a PQ KEM / hybrid mode is planned. Until
  then, do not describe deployments built on this release as "quantum-safe key exchange."
- The README opening and `## Security posture` section both lead with this scope note so it is
  impossible to miss when reading the front page.

## 2. No cloud KMS providers are implemented yet

- Azure Key Vault, AWS KMS, Google Cloud KMS, and PKCS#11/HSM providers are **not** included in
  this release.
- What *is* provided is the extension point: derive from `ContentKeyProvider` and implement
  `WrapKeyAsync` / `UnwrapKeyAsync`. See [`docs/extending-providers.md`](docs/extending-providers.md).
  The local provider is the reference implementation.
- These will ship as separate packages (`PostQuantum.KeyManagement.AzureKeyVault`,
  `PostQuantum.KeyManagement.Aws`, etc.) so the core stays dependency-light. The provisioning steps
  and integration-test layout for each are written out in [`future.md`](future.md).

## 3. Keyring persistence requires you to keep the passphrases

- The local provider holds its key ring **in memory only**; there is no built-in secret store, and
  there never will be one in the core package (storing secrets is the host's job).
- ✅ **`0.2` and later** support **full multi-KEK ring persistence**: `ExportMetadata()` →
  `LocalKeyringMetadata.Encode()` produces a non-secret token (every KEK's salt + Argon2id
  parameters + active KEK id; from `0.3` also a per-KEK HMAC-SHA256 verifier), and
  `LocalContentKeyProvider.Import(...)` rebuilds the whole ring in a later process.
- ✅ **`0.3` and later** ship a `PostQuantum.KeyManagement.Extensions.DependencyInjection` package
  with a `FileKeyringStore` that handles the file persistence (atomic temp+rename) automatically
  when wired through `AddPostQuantumKeyManagement(...)`.
- The remaining responsibility — by design — is **passphrases**. The export deliberately contains
  no key material and no passphrases, so import requires a `PassphraseResolver` that returns the
  passphrase for each KEK id. Store those passphrases yourself (env var, secret manager, prompt).

## 4. KEK identifiers are derived from the salt

- A local KEK's id is `"local-" + hex(SHA-256(salt)[..6])` — a **48-bit** truncation of SHA-256.
  This makes ids stable and reproducible (same salt → same id) without persisting extra state.
- **Collision surface (two distinct salts → same id).** The birthday bound is ≈ 2²⁴, so at the
  enforced `MaxKekCount = 1024` cap the worst-case accidental collision probability is on the
  order of 2⁻²⁹ (≈ 1 in 540 million); at typical operational counts (single digits to ~100) it is
  on the order of 2⁻³⁶ or smaller. Operationally negligible — but **not cryptographically
  astronomical**, which is why we document the actual bound rather than gloss it. A collision is
  refused by `Rotate` (see §7) and detected by Import's salt-id consistency check, so the failure
  mode if one ever occurred would be a clear `InvalidOperationException`, not silent corruption.
  If you want strictly cryptographic margin on KeyIds, widen the truncation in your own fork; the
  default trades 48 bits of id length for short, copy-pasteable identifiers in logs and tokens.
- Consequence (same salt → same id but different key material): two different passphrases used
  with the **same** salt produce the **same** key id but **different** key material. **As of `0.3`**
  this is caught at import time by the per-KEK HMAC-SHA256 verifier (mismatch →
  `InvalidOperationException` naming the offending key id), and also at unwrap time by AES-GCM
  authentication. Tokens written by `0.2` and earlier have no verifier; a wrong passphrase against
  those tokens still surfaces — but only at first unwrap.
- Best practice remains: use distinct salts per KEK (the default when you do not supply one).

## 5. Content-key parameters are fixed

- Content keys are always **256-bit**, and local wrapping is always **AES-256-GCM** with a 96-bit
  nonce and 128-bit tag. These are not yet configurable. They are good defaults; they are simply
  not knobs in the current release.
- Nonces are random per wrap. The per-KEK wrap count is far below the AES-GCM random-nonce safety
  bound for this use (wrapping 32-byte keys), but there is no enforced counter; extremely
  high-volume use should rotate KEKs.

## 6. Memory hygiene is best-effort, not guaranteed

- `ContentKey`, derived passphrase bytes, and intermediate DEK copies are zeroed
  (`CryptographicOperations.ZeroMemory`).
- The .NET managed heap and GC can still copy or relocate buffers, and **`string` passphrases
  cannot be reliably zeroed**. The core passphrase APIs take `ReadOnlySpan<char>` to encourage
  callers to avoid long-lived secret strings; `KeyManagementOptions.Passphrase` in the DI package
  is `string` only because the options-binding pipeline requires it. The runtime offers no hard
  guarantee. On a compromised host, assume in-use keys are exposed.

## 7. Threading model — fully thread-safe (closed in 0.3)

- ✅ **As of `0.3`** `LocalContentKeyProvider` is documented and tested as safe for concurrent
  use. Rotation, wrap, and unwrap serialise on a private lock so a rotating thread cannot dispose
  a KEK that another thread is using. Throughput is unaffected in practice — wrapping a 32-byte
  content key with AES-256-GCM is microseconds.
- `Rotate` with an explicit salt that collides with an existing KEK id throws
  `InvalidOperationException` instead of silently replacing the existing entry. The default
  `Rotate` overload (random salt) is unaffected; collisions there are operationally negligible —
  with the 48-bit truncated KeyId and the `MaxKekCount = 1024` cap the worst-case birthday
  probability is ≈ 2⁻²⁹, and ≈ 2⁻³⁶ or smaller at typical KEK counts. See §4 for the full
  treatment and why we document the actual bound rather than say "astronomical."

## 8. Not independently audited yet

- This is a young preview written with care, automated tests, static analysers, a hostile-input
  test suite, and a published threat model — but it has **not** had a third-party cryptographic
  audit. Treat `0.x` accordingly.
- The plan to commission a review is laid out in [`future.md`](future.md) (engagement paths, scope
  letter, what to publish in the resulting report). It is gated behind cloud-provider stability —
  reviewing a moving target wastes the reviewer's time.

---

## Roadmap (not promises, intentions)

- ✅ **Done in `0.2`:** first-class keyring **export/import** so multi-KEK rotation survives
  process restarts.
- ✅ **Done in `0.3`:** import-time **passphrase verifier**, documented **thread-safety**,
  hostile-input hardening of every token parser, and **work-factor presets** aligned to RFC 9106
  and OWASP.
- ✅ **Done in `0.4`:** `Microsoft.Extensions.DependencyInjection` integration package
  (`AddPostQuantumKeyManagement`, `IKeyringStore` + `FileKeyringStore`, `KeyManagementHealthCheck`),
  three end-to-end samples (Minimal API, Worker Service, EF Core), threat model, versioning
  policy, deployment guide, `TryDecode` overloads for untrusted input, safe `ToString()` on every
  record that carries byte arrays, and Windows-aware atomic file persistence with bounded retry on
  the reader-writer race.
- ✅ **Done in `0.4-preview.2`:** wrong-passphrase verifier widened to 32 bytes (full HMAC-SHA256;
  v3 keyring format with constant-time prefix-compare back-compat for v1 / v2 tokens), README and
  Security Posture rewritten to front-load the honest symmetric-only PQ scope, recommended
  production Argon2id profile pinned in `SECURITY.md` against an offline GPU/ASIC adversary,
  KEK-id collision wording corrected from "astronomical" to the honest birthday bound, and a
  pinned KAT suite anchored to RFC 9106 §A.3.
- The first **cloud KMS provider** (likely Azure Key Vault) as a separate package, validating the
  extension point against a real service.
- The second **cloud KMS provider** (likely AWS KMS) to lock the abstraction in.
- Design work on a **post-quantum / hybrid asymmetric wrapping** layer (ML-KEM) for the KEK tier.
- Configurable content-key size and wrapping algorithm.
- External cryptographic review.
- `1.0` once the above are in real use.

---

*To God be the glory — 1 Corinthians 10:31.*
