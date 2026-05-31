# Known Gaps

This file is the honest counterpart to the README. It lists what `PostQuantum.KeyManagement` does
**not** do yet, what is deliberately out of scope, and where the design has sharp edges. If something
here surprises you *after* you shipped, that is a documentation bug — please open an issue.

Status as of **`0.2.0-preview.1`**.

## 1. "Post-quantum" is currently a symmetric-only claim

- The cryptography that ships in v0.1 is **AES-256-GCM** (wrapping) and **Argon2id** (passphrase
  stretching). Both are considered quantum-resistant *by key size* — Grover's algorithm only halves
  the effective security of a symmetric key, so AES-256 retains ~128-bit post-quantum strength.
- **There is no post-quantum asymmetric primitive here yet.** No ML-KEM (Kyber), no hybrid KEM, no
  PQ signatures. The library name reflects the *family* it belongs to and the direction of travel,
  **not** a claim that v0.1 performs PQ key exchange.
- The asymmetric story matters most for cloud/HSM wrapping (where a KEK wraps a DEK with RSA/ECC) and
  for cross-party key exchange. That is exactly where a PQ KEM / hybrid mode is planned. Until then,
  do not describe deployments built on v0.1 as "quantum-safe key exchange."

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
  parameters + the active KEK id), and `LocalContentKeyProvider.Import(...)` rebuilds the whole ring
  in a later process. This closes the v0.1 gap where only the active KEK's salt was reachable.
- The remaining responsibility — by design — is **passphrases**. The export deliberately contains no
  key material and no passphrases, so import requires a `PassphraseResolver` that returns the
  passphrase for each KEK id. Store those passphrases yourself (env var, secret manager, prompt).
- A wrong passphrase is not detected at import time (the key id is a function of the salt, not the
  passphrase); it surfaces as an `AuthenticationTagMismatchException` at unwrap. See gap #4.

## 4. KEK identifiers are derived from the salt

- A local KEK's id is `"local-" + hex(SHA-256(salt)[..6])`. This makes ids stable and reproducible
  (same salt → same id) without persisting extra state.
- Consequence: two different passphrases used with the **same** salt produce the **same** key id but
  **different** key material. The mismatch is caught safely at unwrap time (AES-GCM authentication
  fails with `AuthenticationTagMismatchException`), not silently — but the ids alone cannot tell two
  such KEKs apart. Use distinct salts per KEK (the default when you do not supply one).

## 5. Content-key parameters are fixed

- Content keys are always **256-bit**, and local wrapping is always **AES-256-GCM** with a 96-bit
  nonce and 128-bit tag. These are not yet configurable. They are good defaults; they are simply not
  knobs in v0.1.
- Nonces are random per wrap. The per-KEK wrap count is far below the AES-GCM random-nonce safety
  bound for this use (wrapping 32-byte keys), but there is no enforced counter; extremely high-volume
  use should rotate KEKs.

## 6. Memory hygiene is best-effort, not guaranteed

- `ContentKey`, derived passphrase bytes, and intermediate DEK copies are zeroed (`CryptographicOperations.ZeroMemory`).
- The .NET managed heap and GC can still copy or relocate buffers, and **`string` passphrases cannot
  be reliably zeroed**. The passphrase APIs take `ReadOnlySpan<char>` to encourage callers to avoid
  long-lived secret strings, but the runtime offers no hard guarantee. On a compromised host, assume
  in-use keys are exposed.

## 7. Threading

- A `LocalContentKeyProvider` instance is **not** documented as thread-safe for concurrent `Rotate`
  calls mixed with wrap/unwrap. Treat configuration changes (rotation) as single-threaded; concurrent
  read-only `CreateContentKeyAsync` / `UnwrapAsync` on a non-rotating provider is fine.

## 8. Not independently audited

- This is a young preview written with care, automated tests, and analyzers — but it has **not** had a
  third-party cryptographic audit. Treat `0.x` accordingly.

---

## Roadmap (not promises, intentions)

- ✅ **Done in `0.2`:** first-class keyring **export/import** so multi-KEK rotation survives process
  restarts (`ExportMetadata` / `Import` / `LocalKeyringMetadata`).
- The first **cloud KMS provider** (likely Azure Key Vault) as a separate package, validating the
  extension point against a real service.
- Design work on a **post-quantum / hybrid asymmetric wrapping** layer (ML-KEM) for the KEK tier.
- Configurable content-key size and wrapping algorithm.

---

*To God be the glory — 1 Corinthians 10:31.*
