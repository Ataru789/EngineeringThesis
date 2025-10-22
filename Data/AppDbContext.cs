using Microsoft.EntityFrameworkCore;
using EngineeringThesis.Models;

namespace EngineeringThesis.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<UserToken> UserTokens => Set<UserToken>();

    public DbSet<DevEmailMessage> DevEmails => Set<DevEmailMessage>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(b =>
        {
            b.Property(u => u.Email).HasMaxLength(254);
            b.Property(u => u.NormalizedEmail).HasMaxLength(254);
            b.Property(u => u.Username).HasMaxLength(20);
            b.Property(u => u.NormalizedUsername).HasMaxLength(20);
            b.Property(u => u.KdfAlgorithm).HasMaxLength(16);
            b.Property(u => u.Prf).HasMaxLength(16);

            b.Property(u => u.PasswordHash).HasColumnType("bytea");
            b.Property(u => u.PasswordSalt).HasColumnType("bytea");

            b.Property(u => u.SecurityAnswerHash).HasColumnType("bytea");
            b.Property(u => u.SecurityAnswerSalt).HasColumnType("bytea");
            b.Property(u => u.TwoFactorSecret).HasColumnType("bytea");

            b.Property(u => u.CreatedAt)
             .HasColumnType("timestamptz")
             .HasPrecision(6)
             .HasDefaultValueSql("now()");

            b.ToTable(t =>
            {
                t.HasCheckConstraint("CK_User_PasswordHash_Len", "octet_length(\"PasswordHash\") = 32");
                t.HasCheckConstraint("CK_User_PasswordSalt_Len", "octet_length(\"PasswordSalt\") = 16");
                t.HasCheckConstraint("CK_User_Iterations_Positive", "\"Iterations\" > 0");
                t.HasCheckConstraint("CK_User_KdfAlgorithm", "\"KdfAlgorithm\" = 'PBKDF2'");
                t.HasCheckConstraint("CK_User_Prf", "\"Prf\" = 'HMACSHA256'");

                t.HasCheckConstraint("CK_User_SecAnsHash_Len", "octet_length(\"SecurityAnswerHash\") = 32");
                t.HasCheckConstraint("CK_User_SecAnsSalt_Len", "octet_length(\"SecurityAnswerSalt\") = 16");
                t.HasCheckConstraint("CK_User_TotpSecret_Len", "octet_length(\"TwoFactorSecret\") = 20");
            });

            b.HasMany(u => u.UserTokens)
             .WithOne(t => t.User)
             .HasForeignKey(t => t.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<UserToken>(b =>
        {
            b.Property(ut => ut.ValueHash).HasColumnType("bytea");

            b.ToTable(t =>
            {
                t.HasCheckConstraint("CK_UserToken_ValueHash_Len", "octet_length(\"ValueHash\") = 32");
            });

            b.HasIndex(ut => new { ut.UserId, ut.UserTokenType, ut.ExpiresAt });
            b.HasIndex(ut => ut.ValueHash).IsUnique();
        });

        modelBuilder.Entity<DevEmailMessage>(b =>
        {
            b.HasIndex(m => m.ToNormalizedEmail);
            b.Property(m => m.ToEmail).HasMaxLength(254);
            b.Property(m => m.ToNormalizedEmail).HasMaxLength(254);
            b.Property(m => m.Subject).HasMaxLength(200);
            b.Property(m => m.CreatedAt).HasColumnType("timestamptz").HasPrecision(6);
            b.Property(m => m.ExpiresAt).HasColumnType("timestamptz").HasPrecision(6);
        });
    }
}
