# CLAUDE.md

Project conventions for `PostQuantum.KeyManagement`. Read this before making changes.

## What this project is

A small, high-level **key management and rotation** library for post-quantum-ready encryption in
.NET. It provides the envelope-encryption abstraction (content keys wrapped by a KEK), a local
Argon2id + AES-256-GCM provider, and extension points for cloud KMS providers. It is a companion to
the other `PostQuantum.*` libraries and is held to the same standard: honest, transparent, disciplined.

## Layout

```
src/PostQuantum.KeyManagement/        # the library (multi-targets net8.0;net9.0;net10.0)
  IContentKeyProvider.cs              # the public contract
  ContentKey.cs / WrappedContentKey.cs# value types (plaintext key + persistable wrapped form)
  ContentKeyProvider.cs               # abstract base: owns the envelope workflow + rotation
  Internal/PortableEncoding.cs        # shared length-prefixed Base64Url token helpers
  Local/                              # the local Argon2id + AES-256-GCM provider
    LocalContentKeyProvider.cs        # provider + keyring Export/Import
    LocalKeyringMetadata.cs           # non-secret, persistable ring description (Encode/Decode)
    LocalKekMetadata.cs / PassphraseResolver.cs
tests/PostQuantum.KeyManagement.Tests/# xUnit round-trip and rotation tests
docs/                                 # deeper guides (e.g. extending-providers.md)
Directory.Build.props                 # repo-wide build settings
```

## Core design rules

- **The base class owns the dangerous parts.** New providers implement *only* `WrapKeyAsync` /
  `UnwrapKeyAsync` plus the three identity properties. Random key generation, `WrappedContentKey`
  assembly, rotation, and provider-ownership checks live in `ContentKeyProvider` and must not be
  duplicated. If a provider needs to change that workflow, change the base class deliberately.
- **`WrappedContentKey` is the only thing callers persist.** It carries no plaintext. Provider-specific
  layout (nonce, tag, etc.) is packed *inside* its `Ciphertext` blob — do not add provider-specific
  public fields to the record.
- **`ContentKey` is sensitive and `IDisposable`.** Anything that produces one hands ownership to the
  caller; anything that holds key bytes internally must zero them (`CryptographicOperations.ZeroMemory`).
- **Passphrases are `ReadOnlySpan<char>`**, never `string`, in public APIs — and are converted to an
  exact-length byte array that is zeroed in a `finally`.

## Engineering standards

- `Nullable`, `ImplicitUsings`, and **`TreatWarningsAsErrors`** are on repo-wide; analyzers run at
  `latest-recommended`. Keep the build at **zero warnings**. The only sanctioned suppression is
  `CA1707` in the *test* project (underscore test names).
- **Every public member is XML-documented.** `GenerateDocumentationFile` is on for the library.
- Builds are **deterministic** with **SourceLink** + symbol packages. Don't regress this.
- Do not add primitives we implement ourselves; rely on the BCL and the vetted Argon2 dependency.

## Tests

- xUnit, in `tests/`. Run with `dotnet test`.
- Tests use deliberately **tiny Argon2id work factors** (`TestDefaults.FastKek`) for speed — never
  copy those values into production guidance.
- New behavior needs a test. Rotation and round-trip are the load-bearing scenarios; keep them green.

## Documentation discipline

- Be honest. Anything the library cannot do yet goes in **KNOWN-GAPS.md** in plain language, including
  the precise scope of the "post-quantum" claim (symmetric-only in v0.1).
- README examples must compile against the real API. If you change a signature, update the README,
  `docs/`, and this file.
- Every top-level doc ends with: `*To God be the glory — 1 Corinthians 10:31.*`

## Versioning

- Currently `0.2.0-preview.1`. Pre-`1.0` the API may change; note breaking changes in
  `PackageReleaseNotes` and the README status section.
- The exported keyring token format is versioned (`FormatVersion` byte). If you change the binary
  layout in `LocalKeyringMetadata` or `WrappedContentKey`, bump that version and keep `Decode`
  able to reject unknown versions.
