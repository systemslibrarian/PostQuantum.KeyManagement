# Security Policy

Cryptography software earns trust by being honest about its limits. This document explains how to
report a problem and what guarantees the library does — and does not — make today. For the running
list of limitations, see [KNOWN-GAPS.md](KNOWN-GAPS.md).

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- Use **GitHub Security Advisories** ("Report a vulnerability") on this repository, or
- email the maintainer privately.

Please include enough detail to reproduce: affected version, target framework, a minimal repro, and
the impact you observed. You will get an acknowledgement, and we will keep you informed as we
investigate, fix, and (with credit, if you wish) disclose.

This is a volunteer, faith-and-craft project — responses are best-effort, but security reports are
always triaged first.

## Supported versions

While in `0.x` preview, only the **latest released version** receives security fixes. There is no
back-porting to older previews before `1.0`.

| Version          | Supported |
| ---------------- | --------- |
| `0.1.0-preview.*`| ✅        |
| older            | ❌        |

## What this library protects

- **Confidentiality & integrity of wrapped keys.** Content keys are wrapped with AES-256-GCM, an
  authenticated cipher. A modified or truncated wrapped key fails to unwrap rather than yielding
  attacker-influenced key material.
- **Strong content keys.** 256-bit keys from the platform CSPRNG (`RandomNumberGenerator`).
- **Brute-force resistance for passphrases.** The local provider stretches passphrases with Argon2id
  (memory-hard), with tunable cost via `LocalKekOptions`.
- **Bounded exposure of plaintext keys.** `ContentKey` zeroes its buffer on `Dispose`; derived
  passphrase bytes and intermediate copies are zeroed after use.

## What it does NOT protect against (today)

- **A compromised host.** If an attacker can read your process memory or your passphrase as it is
  entered, no library can save the keys in use at that moment.
- **Weak passphrases.** Argon2id raises the cost of guessing; it cannot rescue a low-entropy secret.
- **Harvest-now-decrypt-later against asymmetric wrapping.** v0.1 has no asymmetric KEM at all (local
  wrapping is symmetric). When cloud/asymmetric wrapping arrives, classical RSA/ECC wrapping would be
  quantum-vulnerable until a PQ KEM (e.g. ML-KEM) or hybrid mode lands. See KNOWN-GAPS.md.
- **Key/keyring persistence.** Storing salts, KEK metadata, and wrapped keys safely is the caller's
  responsibility in v0.1.

## Cryptographic dependencies

- **AES-256-GCM** and the CSPRNG come from the .NET base class library (`System.Security.Cryptography`).
- **Argon2id** comes from [`Konscious.Security.Cryptography.Argon2`](https://github.com/kmaragon/Konscious.Security.Cryptography).

We do not ship our own implementations of primitives.

## Responsible disclosure

We support coordinated disclosure and are happy to credit reporters. Thank you for helping keep users
safe.

---

*To God be the glory — 1 Corinthians 10:31.*
