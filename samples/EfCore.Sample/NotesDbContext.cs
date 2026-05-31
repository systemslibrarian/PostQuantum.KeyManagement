using Microsoft.EntityFrameworkCore;

namespace EfCore.Sample;

public sealed class NotesDbContext : DbContext
{
    public NotesDbContext(DbContextOptions<NotesDbContext> options) : base(options)
    {
    }

    public DbSet<SecureNote> Notes => Set<SecureNote>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.Entity<SecureNote>(entity =>
        {
            entity.Property(n => n.Title).IsRequired().HasMaxLength(200);
            entity.Property(n => n.Ciphertext).IsRequired();
            entity.Property(n => n.Nonce).IsRequired();
            entity.Property(n => n.Tag).IsRequired();
            entity.Property(n => n.WrappedKey).IsRequired();
        });
    }
}
