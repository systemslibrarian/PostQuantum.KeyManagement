namespace EfCore.Sample;

/// <summary>
/// A persisted entity that stores a "secure" body field as ciphertext alongside the AES-GCM nonce
/// and tag, plus the wrapped DEK as a compact URL-safe token. The plaintext body is never written
/// to the database.
/// </summary>
/// <remarks>
/// <para>
/// This is the explicit pattern — the entity has separate columns for ciphertext, nonce, tag, and
/// the wrapped key. Compared with an EF Core <c>ValueConverter</c>, it has two advantages:
/// </para>
/// <list type="bullet">
///   <item><description>The wrap/unwrap calls are async; <c>ValueConverter</c> is sync only.</description></item>
///   <item><description>You can rotate KEKs without re-encrypting any row — old rows keep their
///   original <c>WrappedKey</c>, which still unwraps under its original KEK in the ring.</description></item>
/// </list>
/// </remarks>
public sealed class SecureNote
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;

    // Envelope-encryption columns. Treat as opaque; never expose to clients.
    public byte[] Ciphertext { get; set; } = [];
    public byte[] Nonce { get; set; } = [];
    public byte[] Tag { get; set; } = [];
    public string WrappedKey { get; set; } = string.Empty;
}
