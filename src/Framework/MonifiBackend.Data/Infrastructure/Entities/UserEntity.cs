using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities
{
    public class UserEntity : BaseActivityEntity
    {
        public string Email { get; set; }
        public string Username { get; set; }
        public string FullName { get; set; }
        public string Avatar { get; set; }
        public string Password { get; set; }
        public bool Terms { get; set; }
        public string ResetPasswordCode { get; set; }
        public int ReferanceUser { get; set; }
        public string ReferanceCode { get; set; }
        public string ConfirmationCode { get; set; }
        public virtual int Role { get; set; }
        public string Fa2Code { get; set; }
        public int LanguageId { get; set; }
        public virtual LanguageEntity Language { get; set; }
        public int CountryId { get; set; }
        public virtual CountryEntity Country { get; set; }
        public virtual ICollection<UserPhoneEntity> Phones { get; set; }
        public virtual ICollection<UserIPEntity> UserIps { get; set; }
        public virtual ICollection<NotificationEntity> Notifications { get; set; }
        public virtual WalletEntity Wallet { get; set; }
    }
    public class UserEntityConfiguration : IEntityTypeConfiguration<UserEntity>
    {
        public void Configure(EntityTypeBuilder<UserEntity> builder)
        {
            builder.ToTable("Users");
            builder.Property(x => x.Email).IsRequired().HasMaxLength(128);
            builder.Property(x => x.Password).IsRequired().HasMaxLength(128);
            builder.Property(x => x.Terms).IsRequired();
            builder.Property(x => x.Role).IsRequired();
            builder.Property(x => x.ResetPasswordCode).HasMaxLength(250);
            builder.Property(x => x.Fa2Code).HasMaxLength(250);
            builder.Property(x => x.ReferanceUser).HasMaxLength(250);
            builder.Property(x => x.ReferanceCode).HasMaxLength(250);
            builder.Property(x => x.ConfirmationCode).HasMaxLength(250);
            builder.Property(x => x.LanguageId).IsRequired();
            builder.Property(x => x.CountryId).IsRequired();
            builder.Property(x => x.Avatar).IsRequired();

            builder.HasMany(x => x.Phones).WithOne(x => x.User);
            builder.HasMany(x => x.UserIps).WithOne(x => x.User);
            builder.HasOne(x => x.Wallet).WithOne(x => x.User);
            builder.HasOne(x => x.Language).WithMany(x => x.Users).HasForeignKey(x => x.LanguageId).OnDelete(DeleteBehavior.NoAction);
            builder.HasOne(x => x.Country).WithMany(x => x.Users).HasForeignKey(x => x.CountryId).OnDelete(DeleteBehavior.NoAction);

            BaseActivityConfiguration.Configure(builder);
        }
    }
}
