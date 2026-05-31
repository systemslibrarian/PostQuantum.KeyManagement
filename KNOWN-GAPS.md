# Known Gaps

This file is the honest counterpart to the README. It lists what `PostQuantum.KeyManagement` does
**not** do yet, what is deliberately out of scope, and where the design has sharp edges. If something
here surprises you *after* you shipped, that is a documentation bug — please open an issue.

Status as of **`0.3.0-preview.1`**.

## 1. "Post-quantum" is currently a symmetric-only claim

- The cryptography that ships here is **AES-256-GCM** (wrapping), **Argon2id** (passphrase
  stretching), and **HMAC-SHA256** (the keyring verifier). All three are considered
  quantum-resistant *by key size* — Grover's algorithm only halves the effective security of a
  symmetric primitive, so AES-256 retains ~128-bit post-quantum strength.
- **There is no post-quantum asymmetric primitive here yet.** No ML-KEM (Kyber), no hybrid KEM, no
  PQ signatures. The library name reflects the *family* it belongs to and the direction of travel,
  **not** a claim that the current release performs PQ key exchange.
- The asymmetric story matters most for cloud/HSM wrapping (where a KEK wraps a DEK with RSA/ECC) and
  for cross-party key exchange. That is exactly where a PQ KEM / hybrid mode is planned. Until then,
  do not describe deployments built on this release as "quantum-safe key exchange."

## 2. No cloud KMS providers are implemented

- Azure Key Vault, AWS KMS, Google Cloud KMS, and PKCS#11/HSM providers are **not** included.
- What *is* provided is the extension point: derive from `ContentKeyProvider` and implement
  `WrapKeyAsync` / `UnwrapKeyAsync`. See `docs/extending-providers.md`. The local provider is the
  reference implementation.
- These will ship as separate packages (`PostQuantum.KeyManagement.AzureKeyVault`, etc.) so the core
  stays dependency-light.

## 3. Keyring persistence requires you to keep the passphrases

- The local provider holds its key ring **in memory only**; there is no built-in secret store, and
  there never will be one in the core package (storing secrets is the host's job).
- As of `0.2`, the **full multi-KEK ring** can be persisted: `ExportMetadata()` →
  `LocalKeyringMetadata.Encode()` produces a non-secret token (every KEK's salt + Argon2id
  parameters + the active KEK id; from `0.3` also a per-KEK HMAC-SHA256 verifier), and
  `LocalContentKeyProvider.Import(...)` rebuilds the whole ring in a later process.
- The remaining responsibility — by design — is **passphrases**. The export deliberately contains no
  key material and no passphrases, so import requires a `PassphraseResolver` that returns the
  passphrase for each KEK id. Store those passphrases yourself (env var, secret manager, prompt).

## 4. KEK identifiers are derived from the salt

- A local KEK's id is `"local-" + hex(SHA-256(salt)[..6])`. This makes ids stable and reproducible
  (same salt → same id) without persisting extra state.
- Consequence: two different passphrases used with the **same** salt produce the **same** key id but
  **different** key material. **As of `0.3`** this is caught at import time by the new per-KEK
  HMAC-SHA256 verifier (mismatch → `InvalidOperationException` naming the offending key id), and
  also at unwrap time by AES-GCM authentication. Tokens written by `0.2` and earlier have no
  verifier; a wrong passphrase against those tokens still surfaces — but only at first unwrap.
- Best practice remains: use distinct salts per KEK (the default when you do not supply one).

## 5. Content-key parameters are fixed

- Content keys are always **256-bit**, and local wrapping is always **AES-256-GCM** with a 96-bit
  nonce and 128-bit tag. These are not yet configurable. They are good defaults; they are simply not
  knobs in the current release.
- Nonces are random per wrap. The per-KEK wrap count is far below the AES-GCM random-nonce safety
  bound for this use (wrapping 32-byte keys), but there is no enforced counter; extremely high-volume
  use should rotate KEKs.

## 6. Memory hygiene is best-effort, not guaranteed

- `ContentKey`, derived passphrase bytes, and intermediate DEK copies are zeroed (`CryptographicOperations.ZeroMemory`).
- The .NET managed heap and GC can still copy or relocate buffers, and **`string` passphrases cannot
  be reliably zeroed**. The passphrase APIs take `ReadOnlySpan<char>` to encourage callers to avoid
  long-lived secret strings, but the runtime offers no hard guarantee. On a compromised host, assume
  in-use keys are exposed.

## 7. Threading model

- **As of `0.3`** `LocalContentKeyProvider` is documented and tested as safe for concurrent use.
  Rotation, wrap, and unwrap serialise on a private lock so a rotating thread cannot dispose a KEK
  that another thread is using. Throughput is unaffected in practice — wrapping a 32-byte content
  key with AES-256-GCM is microseconds.
- `Rotate` with an explicit salt that collides with an existing KEK id now throws
  `InvalidOperationException` instead of silently replacing the existing entry. The default
  `Rotate` overload (random salt) is unaffected; collisions there are astronomical.

## 8. Not independently audited

- This is a young preview written with care, automated tests, static analysers, and a hostile-input
  test suite — but it has **not** had a third-party cryptographic audit. Treat `0.x` accordingly.

---

## Roadmap (not promises, intentions)

- ✅ **Done in `0.2`:** first-class keyring **export/import** so multi-KEK rotation survives process
  restarts (`ExportMetadata` / `Import` / `LocalKeyringMetadata`).
- ✅ **Done in `0.3`:** import-time **passphrase verifier**, documented **thread-safety**,
  hostile-input hardening of every token parser, and **work-factor presets** aligned to RFC 9106
  and OWASP.
- The first **cloud KMS provider** (likely Azure Key Vault) as a separate package, validating the
  extension point against a real service.
- Design work on a **post-quantum / hybrid asymmetric wrapping** layer (ML-KEM) for the KEK tier.
- Configurable content-key size and wrapping algorithm.

---

*To God be the glory — 1 Corinthians 10:31.*
