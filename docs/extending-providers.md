# Extending PostQuantum.KeyManagement with a new provider

This guide shows how to add a content-key provider — for example a cloud KMS or an HSM — by deriving
from `ContentKeyProvider`. The goal of the design is that you write *only* the part that is genuinely
specific to your backend: how a content key is wrapped and unwrapped. Everything else is shared.

## The contract

`ContentKeyProvider` already implements the full `IContentKeyProvider` workflow:

| Concern                                   | Where it lives            |
| ----------------------------------------- | ------------------------- |
| Generating a 256-bit random content key   | `ContentKeyProvider`      |
| Assembling / validating `WrappedContentKey`| `ContentKeyProvider`     |
| Rotation (`RewrapAsync`)                  | `ContentKeyProvider`      |
| Rejecting keys from another provider      | `ContentKeyProvider`      |
| Zeroing transient key material            | `ContentKeyProvider`      |
| **Wrapping a content key**                | **your subclass**         |
| **Unwrapping a content key**              | **your subclass**         |
| **Identity (`ProviderId`, `ActiveKeyId`, `WrapAlgorithm`)** | **your subclass** |

So a new provider has exactly three identity members and two crypto methods to implement.

## Minimal skeleton

```csharp
using PostQuantum.KeyManagement;

public sealed class MyKmsContentKeyProvider : ContentKeyProvider
{
    private readonly IMyKmsClient _client;
    private readonly string _activeKeyId;

    public MyKmsContentKeyProvider(IMyKmsClient client, string activeKeyId)
    {
        _client = client;
        _activeKeyId = activeKeyId;
    }

    // A stable family name. Persisted on every wrapped key; used to route at unwrap time.
    public override string ProviderId => "my-kms";

    // Which KEK new content keys are wrapped under. Change this on rotation.
    public override string ActiveKeyId => _activeKeyId;

    // Recorded on wrapped keys for diagnostics/auditing.
    protected override string WrapAlgorithm => "my-kms-wrap-v1";

    protected override async ValueTask<byte[]> WrapKeyAsync(
        string keyId, ReadOnlyMemory<byte> contentKey, CancellationToken cancellationToken)
    {
        // Send the plaintext content key to the service to be encrypted under `keyId`.
        return await _client.WrapAsync(keyId, contentKey, cancellationToken);
    }

    protected override async ValueTask<byte[]> UnwrapKeyAsync(
        WrappedContentKey wrappedKey, CancellationToken cancellationToken)
    {
        // wrappedKey.KeyId tells you which KEK to use; wrappedKey.Ciphertext is your opaque blob.
        return await _client.UnwrapAsync(wrappedKey.KeyId, wrappedKey.Ciphertext, cancellationToken);
    }
}
```

That is a complete provider. `CreateContentKeyAsync`, `UnwrapAsync`, and `RewrapAsync` now work.

## Rules and gotchas

1. **Treat `Ciphertext` as your private payload.** The base class never inspects it. If your backend
   needs extra parameters to unwrap (IV, key version, wrapping mode), pack them into the `Ciphertext`
   blob yourself — do not add fields to `WrappedContentKey`. The local provider does this: it packs
   `nonce || tag || ciphertext`.

2. **`keyId` in `WrapKeyAsync` is always `ActiveKeyId`.** The base class wraps new keys under the
   active KEK and re-wraps under the active KEK during rotation. Your unwrap path, by contrast, must
   honour whatever `wrappedKey.KeyId` says — older keys reference older KEKs.

3. **Rotation = change `ActiveKeyId`.** Expose a way to point `ActiveKeyId` at a new KEK version. After
   that, new content keys use it automatically, and `RewrapAsync` migrates old ones. You do not
   override `RewrapAsync`.

4. **Don't hold plaintext.** Return freshly allocated byte arrays from `UnwrapKeyAsync`; the base class
   wraps them in a `ContentKey` that the caller disposes. If you must buffer key material internally,
   zero it with `System.Security.Cryptography.CryptographicOperations.ZeroMemory`.

5. **Fail loudly on the wrong KEK.** If `wrappedKey.KeyId` is unknown to your backend, throw. Never
   substitute a different key. (The base class already rejects wrapped keys whose `ProviderId` is not
   yours.)

6. **Ship as a separate package.** Keep backend SDK dependencies (Azure, AWS, …) out of the core
   library. The convention is `PostQuantum.KeyManagement.<Backend>`.

## Testing a new provider

Reuse the shape of the existing suite (`tests/`):

- **Round trip:** `CreateContentKeyAsync` → `UnwrapAsync` returns identical key material.
- **Real data:** encrypt/decrypt a payload with the content key end-to-end.
- **Rotation:** wrap under KEK A, switch active to KEK B, confirm A still unwraps, then `RewrapAsync`
  and confirm the content key is unchanged.
- **Tamper:** a corrupted `Ciphertext` must fail to unwrap, not return garbage.

---

*To God be the glory — 1 Corinthians 10:31.*
