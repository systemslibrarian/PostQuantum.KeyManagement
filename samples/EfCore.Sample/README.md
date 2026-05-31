# EfCore.Sample

A console application showing how to use `PostQuantum.KeyManagement` with EF Core to envelope-encrypt
a column. Each row carries its own DEK, wrapped by the current KEK; rotating the KEK does **not**
require re-encrypting any row.

## What it demonstrates

- A `SecureNote` entity with explicit columns for **ciphertext**, **nonce**, **tag**, and the
  **wrapped DEK** (encoded as the library's URL-safe token). The plaintext body never reaches the
  database.
- A `SecureNotesRepository` that does the encrypt/decrypt at the boundary — clean, explicit, and
  async-compatible (unlike `ValueConverter`, which is sync only).
- A demo run that:
  1. Inserts a note.
  2. Reads it back through the repository (proves round-trip).
  3. Dumps the raw row to show that only ciphertext is on disk.
  4. **Rotates the KEK**, then re-reads the same row — the row's wrapped key still references the
     original KEK, which is still in the ring, so the data is recoverable without re-encryption.

## Running

```bash
cd samples/EfCore.Sample
dotnet run
```

Output looks like:

```
Active KEK at startup: local-df014e81af5e
Inserted note id=1, wrapped under local-df014e81af5e.
Read back: "PSA" -> "Premature rotation is the root of all evil."
Raw row body bytes (hex, first 32): A1B2C3D4E5F6...
Raw row wrapped key: AQVsb2NhbAAAAAxsb2NhbC1kZjAxNGU4MQ...
Rotated KEK -> local-6d0dd1c15340.
Read back after rotation: "PSA" -> "Premature rotation is the root of all evil."
Row's wrapped key still references the original KEK: local-df014e81af5e
```

The first run creates `notes.db` and `keyring.bin` in the working directory. Rerun and the keyring
is loaded from disk — every previously-inserted note is still readable.

## Why this pattern over EF Core `ValueConverter`

A `ValueConverter` looks tempting (a single column appears to be a `string` to the model but is
ciphertext on disk), but it has two real costs:

1. **`ValueConverter` is sync.** A cloud KMS provider's wrap/unwrap is async (a network call); the
   converter API can't accommodate it. You'd be forced to block on async or roll a second sync
   path. The explicit repository in this sample stays async end-to-end.
2. **Per-row DEKs need somewhere to live.** With a `ValueConverter` the DEK is implicit (probably
   shared across the column), which means a KEK rotation forces re-encrypting every row. The
   wrapped-DEK column in this sample is what makes lazy migration possible — each row's DEK is
   independent and can stay wrapped under its original KEK until *that* row is updated.

## Adapting to your store

Swap the connection string in `Program.cs` and add the matching EF Core provider:

```csharp
builder.Services.AddDbContext<NotesDbContext>(o => o.UseNpgsql("Host=...;Database=...;"));
// or
builder.Services.AddDbContext<NotesDbContext>(o => o.UseSqlServer("..."));
```

No other code changes are needed.

---

*To God be the glory — 1 Corinthians 10:31.*
