# future.md — the path to "millions of programmers can use this"

This file is the operational counterpart to the "what's missing" list. It exists because some work
cannot honestly be done from a single coding session — it needs real cloud accounts, a
credentialed reviewer, or a maintainer's social commitment. Everything below is described
concretely enough that the same hand can execute it next.

The numbering matches the recommendation in the chat transcript:

1. **Ship an Azure Key Vault provider** ([§ 1](#1-azure-key-vault-provider))
4. **Ship an AWS KMS provider** ([§ 4](#4-aws-kms-provider))
5. **Get an external cryptographic review** ([§ 5](#5-external-cryptographic-review))
6. **Cut 1.0** ([§ 6](#6-cut-10))

Items 2 (samples) and 3 (deployment guide) are done — see `samples/` and `docs/deployment.md`.

---

## 1. Azure Key Vault provider

### The package

Create `src/PostQuantum.KeyManagement.AzureKeyVault/PostQuantum.KeyManagement.AzureKeyVault.csproj`
with the same multi-targeting + SourceLink + zero-warning discipline as the core. Take a project
reference on the core; add package references:

```xml
<PackageReference Include="Azure.Security.KeyVault.Keys" Version="4.7.0" />
<PackageReference Include="Azure.Identity" Version="1.13.1" />
```

Implement a single class:

```csharp
public sealed class AzureKeyVaultContentKeyProvider : ContentKeyProvider
{
    private readonly CryptographyClient _client;
    private readonly string _keyId;             // e.g. "https://my-vault.vault.azure.net/keys/my-kek/abc123"

    public AzureKeyVaultContentKeyProvider(Uri keyId, TokenCredential credential) { ... }

    public override string ProviderId => "azure-key-vault";
    public override string ActiveKeyId => _keyId;
    protected override string WrapAlgorithm => "RSA-OAEP-256";

    protected override async ValueTask<byte[]> WrapKeyAsync(
        string keyId, ReadOnlyMemory<byte> contentKey, CancellationToken ct)
        => (await _client.WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, contentKey.ToArray(), ct))
            .EncryptedKey;

    protected override async ValueTask<byte[]> UnwrapKeyAsync(
        WrappedContentKey wrappedKey, CancellationToken ct)
        => (await _client.UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, wrappedKey.Ciphertext, ct))
            .Key;
}
```

The pattern is identical to the one already documented in `docs/extending-providers.md`. Key
points:

- Always pin the active key id to a **versioned** key URI (`/keys/my-kek/abc123`), not the
  versionless one. Rotation = create a new key version, point a new provider instance at it,
  rewrap.
- `RSA-OAEP-256` is asymmetric, so Key Vault never returns the unwrapping key to your process. The
  KEK lives in Key Vault; the local provider's KEK lives in your process. That is the security
  upgrade.

### The test environment

You need a real Azure subscription. Local emulators do not cover the cryptography surface; mock
clients are fine for unit tests but not for the integration suite. Bash steps below assume the
Azure CLI; equivalent ARM / Bicep / Terraform paths exist.

#### Provisioning (one-time)

```bash
# Variables you set once
RG="pqkm-test-rg"
LOC="eastus"
KV="pqkm-test-kv-$(openssl rand -hex 4)"   # vault names must be globally unique
KEK="pqkm-test-kek"

# 1. Resource group + vault. RBAC-mode vaults are easier to lock down than access-policy vaults.
az group create --name "$RG" --location "$LOC"
az keyvault create \
  --name "$KV" --resource-group "$RG" --location "$LOC" \
  --enable-rbac-authorization true \
  --enable-purge-protection true \
  --retention-days 7

# 2. The KEK itself. RSA-3072 is the smallest RSA size that's reasonable today; -4096 is fine too.
az keyvault key create \
  --vault-name "$KV" --name "$KEK" \
  --kty RSA --size 3072 \
  --ops wrapKey unwrapKey

# 3. Grant the developer (or a CI service principal) "Crypto User" on this vault.
USER_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)
SCOPE=$(az keyvault show --name "$KV" --query id -o tsv)
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee-object-id "$USER_OBJECT_ID" \
  --scope "$SCOPE"
```

`enable-purge-protection true` is important: it prevents an accidental `az keyvault delete` from
making your test data unrecoverable, which is the same problem you would have in production.

#### Local dev access

`Azure.Identity`'s `DefaultAzureCredential` picks up `az login` credentials, environment variables,
managed identities, etc. After `az login`, the integration suite below works with no extra config.

#### Integration test project

Create `tests/PostQuantum.KeyManagement.AzureKeyVault.IntegrationTests/`:

```csharp
public sealed class AzureKeyVaultIntegrationTests
{
    private static Uri KeyId => new(Environment.GetEnvironmentVariable("PQKM_AZURE_KEY_ID")
        ?? throw new SkipException("PQKM_AZURE_KEY_ID not set; skipping integration test."));

    [SkippableFact]
    public async Task Wrap_Unwrap_RoundTrip()
    {
        var provider = new AzureKeyVaultContentKeyProvider(KeyId, new DefaultAzureCredential());
        using ContentKey created = await provider.CreateContentKeyAsync();
        using ContentKey recovered = await provider.UnwrapAsync(created.WrappedKey);
        Assert.True(CryptographicOperations.FixedTimeEquals(created.Key, recovered.Key));
    }
}
```

Use [`Xunit.SkippableFact`](https://www.nuget.org/packages/Xunit.SkippableFact) so the test is
skipped (not failed) when `PQKM_AZURE_KEY_ID` is unset — CI runs it, contributors without a vault
don't trip over it.

Required test cases at minimum:

- Round-trip (create then unwrap)
- Tamper detection (modify the wrapped blob → unwrap throws)
- Wrong-key rejection (point at a different key, unwrap a blob from the first → throws)
- Rotation through a new key version (wrap under v1, rotate provider to v2, v1 wrapped key still
  unwraps via a second provider instance pinned to v1)
- Cancellation (token cancellation surfaces `OperationCanceledException`, not an opaque Azure SDK
  failure)

#### CI integration

GitHub Actions, using OIDC (preferred over long-lived secrets):

```yaml
permissions:
  id-token: write   # required for OIDC
  contents: read

jobs:
  azure-integration:
    runs-on: ubuntu-latest
    environment: azure-tests  # gates with manual approval if you want
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          client-id:       ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id:       ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 10.0.x
      - run: dotnet test tests/PostQuantum.KeyManagement.AzureKeyVault.IntegrationTests
        env:
          PQKM_AZURE_KEY_ID: ${{ secrets.PQKM_AZURE_KEY_ID }}
```

You set up federated credentials on the service principal once (`az ad app federated-credential
create ...`); no secrets in the repo.

#### What to budget

- Vault: free tier, no data plane charges below trivial thresholds.
- One RSA key: ~$1 / month.
- Integration runs: free on public repos, free-tier minutes on private.

The real cost is your time — call it a half-day to wire it up cleanly, a day if you've never set
up federated OIDC before.

---

## 4. AWS KMS provider

### The package

`src/PostQuantum.KeyManagement.Aws/PostQuantum.KeyManagement.Aws.csproj` — same shape as Azure.
References:

```xml
<PackageReference Include="AWSSDK.KeyManagementService" Version="3.7.401" />
```

Implementation sketch:

```csharp
public sealed class AwsKmsContentKeyProvider : ContentKeyProvider
{
    private readonly IAmazonKeyManagementService _client;
    private readonly string _keyArn;  // e.g. "arn:aws:kms:us-east-1:123456789012:key/abcd1234-..."

    public override string ProviderId => "aws-kms";
    public override string ActiveKeyId => _keyArn;
    protected override string WrapAlgorithm => "AES-GCM-256 / AWS_KMS_ENCRYPT";

    protected override async ValueTask<byte[]> WrapKeyAsync(
        string keyId, ReadOnlyMemory<byte> contentKey, CancellationToken ct)
    {
        var resp = await _client.EncryptAsync(new EncryptRequest
        {
            KeyId = keyId,
            Plaintext = new MemoryStream(contentKey.ToArray()),
        }, ct).ConfigureAwait(false);
        return resp.CiphertextBlob.ToArray();
    }

    protected override async ValueTask<byte[]> UnwrapKeyAsync(
        WrappedContentKey wrappedKey, CancellationToken ct)
    {
        var resp = await _client.DecryptAsync(new DecryptRequest
        {
            KeyId = wrappedKey.KeyId,
            CiphertextBlob = new MemoryStream(wrappedKey.Ciphertext),
        }, ct).ConfigureAwait(false);
        return resp.Plaintext.ToArray();
    }
}
```

Note that AWS KMS's `Encrypt` / `Decrypt` already does authenticated encryption; you do not pack
your own nonce/tag layout. Just persist the `CiphertextBlob` as-is in `WrappedContentKey.Ciphertext`.

### The test environment

```bash
REGION="us-east-1"
ALIAS="alias/pqkm-test-kek"

aws kms create-key \
  --description "PostQuantum.KeyManagement test KEK" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --region "$REGION"

aws kms create-alias \
  --alias-name "$ALIAS" \
  --target-key-id $(aws kms list-keys --region "$REGION" --query 'Keys[-1].KeyId' -o text) \
  --region "$REGION"
```

Use a key policy that grants the test principal only `kms:Encrypt`, `kms:Decrypt`, and
`kms:GenerateDataKey` — nothing else. Production keys should additionally use grants per workload.

CI integration mirrors the Azure shape, with
[`aws-actions/configure-aws-credentials`](https://github.com/aws-actions/configure-aws-credentials)
via OIDC instead of `azure/login`.

Test matrix is the same as Azure: round-trip, tamper, wrong key, rotation through key alias
re-pointing, cancellation.

### Cost

A symmetric KMS key is $1/month plus per-request charges (~$0.03 per 10k requests). Trivial for
testing.

---

## 5. External cryptographic review

### What you need

A reviewer with **published cryptographic engineering experience**, not a generalist security
shop. They are looking for things like:

- Misuse of AES-GCM (nonce reuse, IV-construction sketchiness)
- Misuse of Argon2id (parameters, salt handling, side-channel exposure of derived keys)
- Confidentiality leaks from the verifier construction
- Mistakes in the wire format (length confusion, framing ambiguity)
- Concurrency hazards in the keyring
- Anything in the threat model (`docs/threat-model.md`) that doesn't hold

### How to engage

Two realistic paths:

**a) A named consultant.** Trail of Bits, NCC Group, Latacora, Cure53, and similar firms do
this kind of review. Budget: $15–50k for a library this size, ~2–4 calendar weeks. Get a fixed-fee
quote against a defined scope: this codebase at commit X plus the threat-model + versioning docs.

**b) A community / academic review.** Slower (months) but cheaper. Post on
[the IETF CFRG list](https://mailarchive.ietf.org/arch/browse/cfrg/), [r/crypto](https://www.reddit.com/r/crypto/),
or sponsor a review through an open-source security foundation
([OSTIF](https://ostif.org/) has done libraries of similar scope).

### What to hand them

- This repository at a specific tag (e.g. `v0.5.0-preview.1-for-review`).
- `docs/threat-model.md` (the invariants are what they're auditing).
- `KNOWN-GAPS.md` (so they don't waste time on documented limitations).
- A short scope letter: "Verify the ten invariants in threat-model.md hold against the attacker
  model in § 3. Flag any cryptographic misuse. Out of scope: business logic, DI plumbing, sample
  apps."
- Build instructions and the test suite.

### Outcome

A written report. Publish it (or at least summarise it) in the repo — `docs/audit-report.md` —
along with a CHANGELOG entry that names the reviewer and links their report. That is the trust
signal that makes the difference for risk-averse adopters. A library that has been reviewed and
publishes the report carries enormously more weight than one that claims it has been reviewed.

### When to do it

After cloud providers ship and after a few real deployments have shaken out the corners. Reviewing
a moving target wastes the reviewer's time. Stable surface area + non-trivial real use → review.

---

## 6. Cut 1.0

### The checklist

`1.0` is a social commitment: the public API is stable, breaking changes require a `2.0`, and
security backports happen on a defined schedule. Do not cut it lightly. Before you do:

- [ ] Cloud providers (§ 1, § 4) have shipped and have a non-trivial number of real users.
- [ ] External review (§ 5) is done and the report is published.
- [ ] No `KNOWN-GAPS.md` items are flagged as "tracked for the next breaking release" — anything
      that would change the public API or wire format has either landed or has been explicitly
      deferred to a post-1.0 minor.
- [ ] Wire formats have been stable for at least two minor releases. (Currently
      `WrappedContentKey` v1 is stable since 0.1; `LocalKeyringMetadata` v2 since 0.3.)
- [ ] `docs/versioning.md` SemVer commitments are tightened from "0.x preview" to "1.x strict".
- [ ] `SECURITY.md` declares a backport policy (e.g. "security fixes are backported to the
      previous minor for 12 months after a new minor ships").
- [ ] A test suite + restore drill exists and passes on every supported TFM in CI.
- [ ] At least one production deployment has run the library for a meaningful window without
      incident, and the maintainer can name it (publicly or to the auditor).

### The bump

When the checklist is green, the release itself is mechanical:

```
git tag v1.0.0
git push origin v1.0.0
```

…with a `Version` bump in each csproj and a CHANGELOG entry. The hard part isn't the bump; it's
earning it.

### What 1.0 obligates the maintainer to

- **No breaking API changes** without a `2.0`. SemVer is a promise to the ecosystem.
- **Format-version readers stay backward-compatible** for at least one major version.
- **Security backports** per the published policy.
- **Deprecation cycles.** Anything you want to remove later has to be marked `[Obsolete]` in `1.x`
  for at least a minor before it goes away in `2.0`.

These obligations are why "should we cut 1.0?" deserves a real answer, not a default-yes.

---

## Sequencing

The natural order is:

1. **Azure provider** — proves the extension point works against a real KMS; surface API likely
   adjusts slightly in response (e.g. the `IContentKeyProvider` may need a disposal contract for
   network-backed implementations).
2. **AWS provider** — second cloud locks the abstraction in; if it requires changes to the base
   class, do them now while still in 0.x.
3. **Production deployment guide reviewed against real cloud users.** This guide
   (`docs/deployment.md`) was written before cloud providers existed; revisit it with the cloud
   sections expanded once both providers ship.
4. **External review** — only after the surface is stable.
5. **1.0** — only after the external review.

Don't reorder. Each step's value depends on the previous one being done.

---

*To God be the glory — 1 Corinthians 10:31.*
