# WorkerService.Sample

A .NET worker service showing the operational shape of `PostQuantum.KeyManagement`: liveness
probing, scheduled rotation, and durable keyring persistence — exactly what an ops team needs to
trust the library in production.

## What it demonstrates

- **`LivenessWorker`** mints a content key every 10 seconds, encrypts a probe payload, then
  unwraps it and decrypts. A failure here is an early warning that something is wrong with the
  provider, the keyring, or the host's entropy source. Each tick logs the round-trip latency and
  the active KEK id — feed those to an ops dashboard.
- **`RotationWorker`** rotates the active KEK on a configurable interval (default 2 minutes; the
  Development environment overrides to 30 seconds so the behaviour is visible at demo speed) and
  persists the updated keyring through the registered `IKeyringStore`. Production cadence is days
  to weeks; the same wiring still applies.
- **`FileKeyringStore`** keeps the multi-KEK ring durable across restarts; killing the worker and
  starting it again preserves the ability to unwrap data wrapped under earlier KEKs.

## Running

```bash
cd samples/WorkerService.Sample
DOTNET_ENVIRONMENT=Development dotnet run
```

You'll see something like:

```
info: WorkerService.Sample.LivenessWorker[0]
      Liveness worker starting. Initial active KEK: local-df014e81af5e
info: WorkerService.Sample.RotationWorker[0]
      Rotation worker armed. Interval: 00:00:30.
info: WorkerService.Sample.LivenessWorker[0]
      Liveness probe OK in 0.4 ms. Active KEK: local-df014e81af5e
...
info: WorkerService.Sample.RotationWorker[0]
      Rotated KEK: local-df014e81af5e -> local-6d0dd1c15340.
info: WorkerService.Sample.RotationWorker[0]
      Persisted updated keyring to the configured store.
info: WorkerService.Sample.LivenessWorker[0]
      Liveness probe OK in 0.4 ms. Active KEK: local-6d0dd1c15340
```

Stop with Ctrl+C, then start again — the worker picks up the keyring from disk and continues
rotating from where it left off.

## Adapting to production

- **Replace the rotation passphrase source.** The sample appends a tick counter to the existing
  passphrase for demonstration. In production, integrate a secret manager (Azure Key Vault, AWS
  Secrets Manager, HashiCorp Vault, a key-derivation HSM) that vends a fresh high-entropy secret
  per rotation. Never let the passphrase be predictable.
- **Choose a rotation cadence that matches your threat model.** Rotating too often loads the
  provider for no benefit; rotating too rarely defeats the point. A common starting point is
  every 90 days for KEKs and per-record-or-session for DEKs (DEKs are minted by
  `CreateContentKeyAsync`, so that's already automatic).
- **Wire the liveness probe into your health/readiness endpoint.** ASP.NET Core hosts can use the
  `KeyManagementHealthCheck` exported from `PostQuantum.KeyManagement.Extensions.DependencyInjection`
  instead of running a separate background probe.
- **Back up the keyring file.** Losing it makes every wrapped key permanently unrecoverable. See
  [`docs/deployment.md`](../../docs/deployment.md) for the full operational checklist.

---

*To God be the glory — 1 Corinthians 10:31.*
