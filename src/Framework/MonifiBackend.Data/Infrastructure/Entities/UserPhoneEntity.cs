using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class UserPhoneEntity : BaseActivityEntity
{
    public int UserId { get; set; }
    public string Number { get; set; }
    public virtual UserEntity User { get; set; }
}
public class UserPhoneEntityConfiguration : IEntityTypeConfiguration<UserPhoneEntity>
{
    public void Configure(EntityTypeBuilder<UserPhoneEntity> builder)
    {
        builder.ToTable("UserPhones");
        builder.Property(x => x.Number).IsRequired().HasMaxLength(128);

        builder.HasOne(x => x.User).WithMany(x => x.Phones).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.NoAction);

        BaseActivityConfiguration.Configure(builder);
    }
}
