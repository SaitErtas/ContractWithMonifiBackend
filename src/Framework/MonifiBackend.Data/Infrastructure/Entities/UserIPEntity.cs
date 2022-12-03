using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class UserIPEntity : BaseActivityEntity
{
    public int UserId { get; set; }
    public string IpAddress { get; set; }
    public string RequestName { get; set; }
    public virtual UserEntity User { get; set; }
}
public class UserIPEntityConfiguration : IEntityTypeConfiguration<UserIPEntity>
{
    public void Configure(EntityTypeBuilder<UserIPEntity> builder)
    {
        builder.ToTable("UserIPs");
        builder.Property(x => x.IpAddress).IsRequired().HasMaxLength(250);
        builder.Property(x => x.RequestName).IsRequired().HasMaxLength(250);

        builder.HasOne(x => x.User).WithMany(x => x.UserIps).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.NoAction);

        BaseActivityConfiguration.Configure(builder);
    }
}