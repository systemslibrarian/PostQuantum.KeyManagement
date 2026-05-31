# Production deployment guide

This is the operational companion to [`threat-model.md`](threat-model.md). The threat model says
*what* the library defends against; this document says *what you have to do* to keep those
properties true in real deployments.

Status as of **`0.3.0-preview.1`**.

If you only have time to read one section, read **§ 3. The four things you absolutely must get
right.** Everything else is detail in service of those four.

---

## 1. Mental model

`PostQuantum.KeyManagement` separates three concerns. Treat each on its own.

| Concern              | Lives where                                  | Loss means                                  |
| -------------------- | -------------------------------------------- | ------------------------------------------- |
| **Passphrase**       | Your secret store (env var, KMS, vault)      | Recoverable iff you can re-derive the KEK   |
| **Keyring metadata** | A durable file / object the host can read   | **Permanent loss of all wrapped data**      |
| **Wrapped keys + ciphertext** | Your application database / blob store | Recoverable iff the matching KEK is alive  |

The keyring metadata is non-secret but **load-bearing**. Without it (or without the passphrases
that derive the same KEKs), every wrapped key in your database becomes unrecoverable bytes. Plan
backups accordingly.

## 2. Where each piece goes

### Passphrase

- **Production:** a secret manager (Azure Key Vault Secrets, AWS Secrets Manager, GCP Secret
  Manager, HashiCorp Vault, Kubernetes Secrets mounted as files). Inject via environment variable
  or a configuration provider that hits the secret manager at startup.
- **Local dev:** environment variables or `dotnet user-secrets`. Never check passphrases into
  `appsettings.json`.
- **Never:** in source control, in a Docker image layer, in `appsettings.*.json` checked into the
  repo, in CI logs, in `--env` flags visible from `docker inspect`.

`KeyManagementOptions.Passphrase` is a `string` because configuration binding requires it; the
library converts it to a byte buffer and zeroes the buffer after derivation. The original `string`
itself cannot be reliably zeroed in .NET — this is unavoidable on the managed runtime — so minimise
its lifetime: read it once at startup, never log it, never include it in diagnostics.

### Keyring metadata (`LocalKeyringMetadata`)

- **Production:** durable storage with snapshots/backups: a file on a volume that is itself backed
  up; an object store with versioning enabled (S3 with versioning, Azure Blob Storage with
  soft-delete); a database table.
- **The default `FileKeyringStore`** is fine for single-instance deployments. It writes atomically
  (temp + `File.Replace`), so a crash mid-write can't poison the file — but it cannot, by itself,
  protect you from disk loss. Pair it with backups.
- **Multi-instance deployments** need a shared keyring; see § 6.

### Wrapped keys + ciphertext

These are the per-record / per-blob outputs your application produces: store them next to the data
they protect. They are safe to persist next to ciphertext — that's the whole point of envelope
encryption. The integrity of the wrap is guaranteed by AES-GCM (see threat-model.md, I-1).

## 3. The four things you absolutely must get right

1. **The passphrase is not on disk anywhere except your secret manager.** Once a passphrase is in
   a Docker layer, a CI log, or `appsettings.json` in git, it is compromised. Rotate.
2. **The keyring metadata is backed up.** Loss of `keyring.bin` is equivalent to loss of every row
   that depends on it. Snapshot the volume / enable bucket versioning / mirror the file to a second
   region. Test restoring from the backup at least once.
3. **Rotation is automated, not a manual step.** A KEK that should have been rotated 18 months ago
   but wasn't is the standard pattern for "we got breached and our keys are still valid." Use the
   [`WorkerService.Sample`](../samples/WorkerService.Sample) as the template; wire the new
   passphrase to a fresh secret per rotation.
4. **You have a tested restore procedure.** A backup you've never restored from is a backup you
   don't have. Run a "lose the host, restore from backups, decrypt a known record" drill.

## 4. Argon2id work factor in production

The `LocalKekOptions` presets are tuned to RFC 9106 / OWASP:

| Preset       | Memory | Iterations | Parallelism | Typical use                                        |
| ------------ | ------ | ---------- | ----------- | -------------------------------------------------- |
| `Interactive`| 64 MiB | 3          | 4           | Server-side default. Latency ~100–300 ms.          |
| `Moderate`   | 256 MiB| 4          | 4           | Background jobs, admin operations. ~0.5–1 s.       |
| `Sensitive`  | 2 GiB  | 1          | 4           | Long-lived master KEKs. Several seconds.           |
| `LowMemory`  | 19 MiB | 2          | 1           | OWASP minimum; constrained hosts only.             |

Choose based on **how often you derive**, not on "how secure" each preset feels:

- **Once at startup** → `Sensitive` is fine. The host pays the cost once.
- **Once per request** → never derive on the request path. Cache the provider as a singleton.
- **Once per rotation** → `Moderate` or `Sensitive`. Rotations are rare; pay the cost.

Whatever you choose is recorded per-KEK in the keyring metadata, so future imports reproduce the
exact same KEK. Changing the preset later does **not** invalidate older KEKs.

## 5. Monitoring and observability

### What to expose

- **`/health` (or equivalent).** Wire `KeyManagementHealthCheck` — it does a real wrap/unwrap on
  every check and degrades to `Unhealthy` if the provider throws. Use it as a readiness probe;
  failing reads should stop traffic, not just log.
- **Active KEK id.** Expose it as a metric label or a startup log line. A surprise change is
  either rotation working or something interesting going wrong; both deserve visibility.
- **Rotation timestamps.** Log every rotation with `{previousKeyId, newKeyId, timestamp}`.
- **Liveness probe duration.** If a wrap/unwrap suddenly takes 10x longer than usual, you have a
  problem with the host's entropy source, the KMS service, or the disk holding your keyring.

### What NOT to log

- Passphrases. Ever. Not in plaintext, not Base64, not "for debugging".
- DEK bytes. `ContentKey.Key` is `ReadOnlySpan<byte>` precisely to make logging awkward; don't
  reach around it by `.ToArray()` and `Convert.ToHexString`.
- The contents of any `ContentKey` regardless of how it was obtained.

Wrapped keys, KEK ids, and keyring metadata are **non-secret** — log them freely; they are what
your dashboard needs to debug the system.

## 6. Multi-instance deployments

A single `LocalContentKeyProvider` instance is per-process. With more than one host, you have two
realistic options:

### Option A — shared keyring file (read-mostly)

Every instance reads the same `keyring.bin` at startup. Rotation is done by **exactly one** host
(a designated worker or admin), which writes the new keyring; other hosts pick it up on next
restart or via a config reload signal.

- **Pros:** simple, no extra infrastructure.
- **Cons:** rotated KEKs aren't visible to other hosts until they reload. A request that hits an
  old host with a wrapped key from a brand-new KEK will fail (the old host doesn't have it yet).
  Either tolerate this during the rotation window, or implement a "reload signal" via SIGHUP /
  Kubernetes ConfigMap reload / etc.

### Option B — shared keyring + dedicated rotator service

A dedicated rotator service (the [`WorkerService.Sample`](../samples/WorkerService.Sample) is the
template) owns rotation. All other services consume the keyring read-only and reload when the
underlying file/blob changes. This is the production pattern for serious deployments.

### What does NOT work

- Sharing only the passphrase without the keyring. Each host would derive its own keyring with its
  own random salts at startup, and the resulting KEKs would not match across hosts.
- Sharing the passphrase + a fixed salt — yes, that produces a stable KEK across hosts, but a
  multi-KEK ring (the whole point of rotation) is now impossible.
- Letting two hosts both rotate. The losers' rotations are silently lost when the winner writes.

For deployments that need stronger guarantees than this section provides — atomic rotation across a
fleet, automatic key escrow, audit trails — use a cloud KMS provider (when shipped; tracked in
`future.md`) instead of the local provider.

## 7. Containers and Kubernetes

- **Passphrase via Kubernetes Secret + projected volume**, or via the cloud provider's secret
  manager + workload identity. Never via `env:` in the pod spec (those are visible to anyone with
  `get pods` RBAC).
- **Keyring on a PersistentVolume** for single-instance services, or on object storage for fleets.
  Persistent volumes need their own snapshot policy.
- **Don't bake the passphrase into the container image.** Multi-stage builds make this easy to do
  by accident; check final image layers for unexpected `ENV` directives.
- **Set `readOnlyRootFilesystem: true`** with a tmpfs `/tmp` and a writable mount only for the
  keyring path. Limits blast radius if the app is compromised.

## 8. Backup and disaster recovery

The keyring metadata is the only artefact whose loss is unrecoverable. Treat it like the database
that holds your encryption keys, because that is exactly what it is.

| Recovery scenario                              | What you need                                |
| ---------------------------------------------- | -------------------------------------------- |
| Host disk fails                                | Backup of the keyring file or shared store   |
| Region/data-centre fails                       | Cross-region replication of the keyring      |
| Operator accidentally rotates with bad passphrase | The previous keyring blob, or the previous passphrase |
| Compromise — passphrase leaked                 | New passphrase, rotate via `LocalContentKeyProvider.Rotate`, then `RewrapAsync` all wrapped keys onto the new KEK at your leisure (data ciphertext stays unchanged) |
| Compromise — keyring exfiltrated               | The keyring is non-secret in itself, but rotate passphrases anyway: the attacker now knows the salts and parameters, which is half the work of a passphrase brute-force |
| Lost the keyring AND the passphrases           | Data is unrecoverable. There is no back door. |

### Restore drill (do this before you need it)

1. Provision a clean host.
2. Restore `keyring.bin` from your backup.
3. Provide the passphrase(s) via your secret store.
4. Run a script that loads a known-wrapped record from the database and decrypts it.
5. Verify the plaintext matches.
6. Document the elapsed time and any gaps.

A restore drill that has never been run is not a restore drill.

## 9. Upgrade and migration

- Stay within the same minor version line until you've validated the upgrade against your test
  suite + restore drill.
- Format-version policy (`docs/versioning.md`) guarantees that wrapped keys and keyring tokens from
  one minor version still decode on the next. Forward compatibility is not promised — a 0.3 reader
  does not decode 0.4 formats. Plan upgrades, don't surprise the production fleet with them.

## 10. What this library does NOT do for you

- **It does not store your passphrase.** That's your secret manager's job.
- **It does not back up your keyring.** That's your backup strategy's job.
- **It does not rotate on a schedule.** That's a worker / scheduled job — see the worker sample.
- **It does not detect a stolen keyring.** That's your audit log + DLP.
- **It does not log itself.** It is silent by design (no surprise log lines containing key
  material). You wire the visibility you need; this guide tells you what to wire.

---

*To God be the glory — 1 Corinthians 10:31.*
