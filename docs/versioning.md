# Versioning and compatibility policy

Calling code, persisted data, and the network wire format all have to keep working across upgrades.
This file describes what we promise — and what we don't — at each layer.

Status as of **`0.3.0-preview.1`**.

## 1. Package version

`PostQuantum.KeyManagement` follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html),
with one explicit caveat: while
the major version is `0`, the API surface may change between minor versions, and we will document
every such change in `CHANGELOG.md`.

| Phase                          | Stability of public API | Stability of wire formats     |
| ------------------------------ | ----------------------- | ----------------------------- |
| `0.x` (preview)                | May change with notice  | Versioned; readers stay backward-compatible across minor versions |
| `1.0` and later                | SemVer strict           | Versioned; format changes require a major bump or a new version byte |

## 2. Wire formats

Two encoded blobs are produced by the library and may be persisted by callers:

- `WrappedContentKey.Encode()` — the URL-safe Base64 token for a single wrapped key.
- `LocalKeyringMetadata.Encode()` — the URL-safe Base64 token for the keyring's non-secret
  structure.

Both formats are length-prefixed binary blobs whose first byte is the **format version**.

| Format                       | Current version | Earlier versions readable | Notes |
| ---------------------------- | --------------- | ------------------------- | ----- |
| `WrappedContentKey`          | `1`             | n/a (only one version)    | The blob inside `Ciphertext` is provider-specific; the local provider stores `nonce ‖ tag ‖ ciphertext`. |
| `LocalKeyringMetadata`       | `2`             | `1`                       | v2 added a per-KEK HMAC-SHA256 verifier for import-time passphrase detection. v1 still decodes; v1 imports just skip the import-time check. |

### Format-version policy

- **Adding fields** to a format requires bumping the version byte.
- **Decoders** must accept all versions they understand and reject everything else with
  `FormatException`. They must never *guess* at a version they don't recognise.
- **Encoders** always write the current version on this library release; we do not provide
  legacy-format emitters.
- **Readers stay backward-compatible across at least one minor version.** A `0.4` release decodes
  every format byte that `0.3` could write.
- **Forward compatibility is not promised.** A `0.3` reader does not decode `0.4` formats; it
  refuses cleanly.

A format change is also documented in `CHANGELOG.md` and noted in the relevant `xxxFormatVersion`
constant on the encoded type.

## 3. API surface

### Public types

These types are part of the public API. Breaking changes to any of them require a major version
bump (after `1.0`) or a documented entry in `CHANGELOG.md` (before `1.0`):

- `IContentKeyProvider`
- `ContentKeyProvider` (extension point)
- `ContentKey`, `WrappedContentKey`
- `LocalContentKeyProvider`, `LocalKekOptions`, `LocalKekMetadata`, `LocalKeyringMetadata`,
  `PassphraseResolver`
- `KeyManagementOptions`, `KekWorkFactor`, `IKeyringStore`, `FileKeyringStore`,
  `KeyManagementHealthCheck`
- `KeyManagementServiceCollectionExtensions`, `KeyManagementHealthChecksBuilderExtensions`

### Internal types

The `PostQuantum.KeyManagement.Internal` namespace is **not** public API. Anything under it can
change in any release without notice.

### Subclassing `ContentKeyProvider`

The extension contract is documented in `docs/extending-providers.md`. We treat changes to the
abstract methods (`WrapKeyAsync`, `UnwrapKeyAsync`) and the protected helper
(`EnsureOwnedByThisProvider`) as breaking and bump accordingly.

## 4. Target frameworks

Each release multi-targets the .NET LTS in support plus the current STS and the next-up LTS:

| Release line   | Target frameworks      |
| -------------- | ---------------------- |
| `0.3.x`        | `net8.0;net9.0;net10.0`|

When .NET 12 ships, `0.x` releases continue to target the same set; a major bump may drop the
oldest TFM. We will not drop a TFM mid-line.

## 5. Support and security backports

While in `0.x` preview, only the **latest released version** receives security fixes (see
`SECURITY.md`). After `1.0`, security backports follow the schedule announced at that release.

## 6. What is *not* covered by SemVer

- **Behaviour under undefined inputs.** Passing a tampered token to `Decode` and getting a
  `FormatException` is contract; the specific message is not.
- **Performance characteristics.** A patch release may make `LocalContentKeyProvider` faster or
  slower at deriving a KEK. The order of magnitude (sub-second for `Interactive` work factor)
  remains.
- **Log output.** The library does not log anything itself yet; if/when it does, log lines are not
  part of SemVer.

---

*To God be the glory — 1 Corinthians 10:31.*
