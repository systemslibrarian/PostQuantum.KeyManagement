using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PostQuantum.KeyManagement;

namespace EfCore.Sample;

/// <summary>
/// Wraps a <see cref="NotesDbContext"/> with envelope-encryption operations. Plaintext bodies
/// never cross the persistence boundary; the database only sees ciphertext + nonce + tag + the
/// wrapped DEK token.
/// </summary>
public sealed class SecureNotesRepository
{
    private readonly NotesDbContext _db;
    private readonly IContentKeyProvider _keys;

    public SecureNotesRepository(NotesDbContext db, IContentKeyProvider keys)
    {
        _db = db;
        _keys = keys;
    }

    /// <summary>Creates a new note, encrypting <paramref name="body"/> with a freshly minted DEK.</summary>
    public async Task<int> CreateAsync(string title, string body, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(title);
        ArgumentNullException.ThrowIfNull(body);

        byte[] plaintext = Encoding.UTF8.GetBytes(body);
        byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

        SecureNote note;
        using (ContentKey key = await _keys.CreateContentKeyAsync(cancellationToken).ConfigureAwait(false))
        {
            using var aes = new AesGcm(key.Key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

            note = new SecureNote
            {
                Title = title,
                Ciphertext = ciphertext,
                Nonce = nonce,
                Tag = tag,
                WrappedKey = key.WrappedKey.Encode(),
            };
        }

        _db.Notes.Add(note);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return note.Id;
    }

    /// <summary>Loads a note by id and returns its decrypted body. Returns null if no such row exists.</summary>
    public async Task<(string Title, string Body)?> GetAsync(int id, CancellationToken cancellationToken = default)
    {
        SecureNote? note = await _db.Notes.AsNoTracking()
            .FirstOrDefaultAsync(n => n.Id == id, cancellationToken).ConfigureAwait(false);
        if (note is null)
        {
            return null;
        }

        WrappedContentKey wrapped = WrappedContentKey.Decode(note.WrappedKey);
        byte[] plaintext = new byte[note.Ciphertext.Length];
        using (ContentKey key = await _keys.UnwrapAsync(wrapped, cancellationToken).ConfigureAwait(false))
        {
            using var aes = new AesGcm(key.Key, note.Tag.Length);
            aes.Decrypt(note.Nonce, note.Ciphertext, note.Tag, plaintext);
        }

        return (note.Title, Encoding.UTF8.GetString(plaintext));
    }
}
