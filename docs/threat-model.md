# Threat model

This document is the precise companion to `SECURITY.md`. `SECURITY.md` says what to do; this says
*what we believe, what we assume, and what we do not defend against*. If your deployment violates
an assumption listed here, the security properties below no longer hold — read carefully.

Status as of **`0.3.0-preview.1`**.

## 1. Assets

We protect, in priority order:

1. **Plaintext content keys (DEKs).** 256-bit symmetric keys used to encrypt application data.
2. **Key-encryption keys (KEKs).** Argon2id-derived 256-bit keys held in memory; never persisted.
3. **Passphrases.** Caller-supplied; converted to byte buffers, used, and zeroed.
4. **Wrapped content keys.** Authenticated ciphertexts produced by the KEK; safe to persist.
5. **Keyring metadata.** Salts, Argon2id parameters, KEK ids, and the per-KEK verifier; safe to
   persist.

## 2. Trust boundary

Everything **inside the process** running this library is trusted. Everything **outside** the
process is untrusted, including persistent storage of wrapped keys and keyring metadata.

## 3. Attacker model

We assume an attacker who can:

- Read every wrapped key (`WrappedContentKey.Ciphertext`) the application has ever persisted.
- Read every exported `LocalKeyringMetadata` blob, including all salts, Argon2id parameters, and
  KEK verifiers.
- Tamper arbitrarily with both above before they reach us at unwrap / import time.
- Mount adaptive chosen-ciphertext attacks against `UnwrapAsync` — i.e. submit any blob, even ones
  derived from observed ciphertexts, and observe whether decryption succeeded or failed.
- Send arbitrary, malformed, or maliciously crafted encoded tokens to any `Decode` method.
- Concurrently invoke any public member from many threads.

We assume an attacker who **cannot**:

- Read the process's memory while it is running.
- Read the passphrase from wherever the host stores it (env var, secret manager, prompt). This is
  the host's responsibility; we cannot defend against compromise of the secret store.
- Compute a preimage or break standard cryptographic assumptions for AES-256, SHA-256, HMAC-SHA256,
  or Argon2id at currently-recommended cost factors.
- Observe Argon2id execution side-channels (cache timing, power analysis). Side-channel resistance
  is the implementation library's responsibility (`Konscious.Security.Cryptography.Argon2`); we do
  not implement Argon2id ourselves.

## 4. Security invariants

These are properties the library is designed to hold under the attacker model above. Failure of any
of them is a security bug; please report privately per `SECURITY.md`.

| ID  | Invariant |
| --- | --- |
| **I-1** | A wrapped key whose `Ciphertext` is modified in any single bit will fail authentication. AES-GCM's integrity is the load-bearing primitive. |
| **I-2** | A wrapped key tagged with a `KeyId` that is unknown to the loaded provider raises `KeyNotFoundException`; the wrapped key is never decrypted under a different KEK. |
| **I-3** | A wrapped key tagged with a `ProviderId` other than this provider's raises `InvalidOperationException` before any cryptographic operation occurs. |
| **I-4** | The plaintext byte buffer behind every `ContentKey` is zeroed when the `ContentKey` is disposed (`CryptographicOperations.ZeroMemory`). |
| **I-5** | Derived passphrase byte buffers are zeroed in a `finally` block, even on exception. |
| **I-6** | Token decoders (`WrappedContentKey.Decode`, `LocalKeyringMetadata.Decode`) reject negative lengths, lengths greater than the remaining buffer, lengths above `PortableEncoding.MaxFieldLength`, and KEK counts above `LocalKeyringMetadata.MaxKekCount`. Overflow-safe arithmetic (subtraction, not addition) is used for bounds checks. |
| **I-7** | The local-provider unwrap path rejects payload sizes that, after the 12-byte nonce and 16-byte tag, are not exactly 32 bytes. |
| **I-8** | A KEK whose persisted `Verifier` (v2 keyring tokens) does not match the verifier recomputed from the supplied passphrase causes `LocalContentKeyProvider.Import` to throw before the KEK is added to the ring; the comparison is constant-time. |
| **I-9** | `LocalContentKeyProvider` is safe for concurrent use. Wrap, unwrap, rotate, and dispose serialise on a private lock so a rotating thread cannot dispose a KEK that another thread is actively using. |
| **I-10** | `Rotate` refuses to silently replace a KEK that already exists in the ring (collision on the salt-derived key id), preserving the ability to unwrap data previously wrapped under that KEK. |

## 5. Out-of-scope threats

We do **not** defend against the following — they are real, but they are outside what a library can
solve. We list them so deployments can address them at the appropriate layer.

- **Host compromise.** If an attacker reads process memory or scrapes the passphrase from the host
  (e.g. via a debugger, swap file, container introspection), no library can protect keys in use.
- **Weak passphrases.** Argon2id raises the cost of brute force, but a low-entropy passphrase
  still falls to dictionary attacks. Use 20+ random characters from a CSPRNG, or a high-entropy
  passphrase generator. Argon2id is not a substitute for entropy.
- **`string`-typed passphrases.** Public APIs take `ReadOnlySpan<char>` precisely because `string`
  cannot be reliably zeroed in .NET. Callers that hand the library a `string` accept that the
  passphrase may persist in the managed heap until GC reclaims it (and possibly longer if pinned).
- **Side-channel attacks on Argon2id.** Cache-timing and power-analysis resistance are properties
  of the underlying Argon2 implementation, not this library.
- **Quantum attacks on asymmetric primitives.** v0.3 ships no asymmetric KEM. If/when one is added,
  classical RSA/ECC wrapping would be quantum-vulnerable until a PQ KEM (e.g. ML-KEM) or hybrid
  mode lands; see `KNOWN-GAPS.md`.
- **Compromise of the persistence layer.** A wrapped key with a destroyed KEK is unrecoverable.
  Back up keyring metadata; treat its loss as equivalent to losing the data it protects.
- **Misuse of the cryptographic primitives by the caller.** If the caller reuses an AES-GCM nonce
  with the same DEK they cause a catastrophic break of that DEK; the library mints fresh DEKs to
  make nonce reuse statistically impossible *for the library's own KEK-wrapping operations*, but
  callers using DEKs to encrypt application data are responsible for nonce discipline there.

## 6. Format stability

The wire formats produced by `WrappedContentKey.Encode` and `LocalKeyringMetadata.Encode` carry an
explicit single-byte format-version prefix. Format-version changes follow the policy in
`docs/versioning.md`. Decoders reject unknown versions rather than guessing.

## 7. What is *not* a vulnerability

We expect to see these reports occasionally; they are intentional behaviour, not bugs.

- A wrapped key persisted by an external system that does not match the local provider's blob
  layout fails to unwrap with a `CryptographicException`. That is correct refusal, not a bug.
- A `ContentKey` accessed after `Dispose` throws `ObjectDisposedException`. The buffer has been
  zeroed by then; this protects against use-after-zero.
- `Rotate` throwing on a key-id collision is intentional defence against accidental destructive
  rotation (see I-10).

---

*To God be the glory — 1 Corinthians 10:31.*
