using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class NotificationEntity : BaseActivityEntity
{
    public int UserId { get; set; }
    public string Message { get; set; }
    public bool IsRead { get; set; }
    public string CustomerName { get; set; }
    public decimal Price { get; set; }
    public virtual UserEntity User { get; set; }
}
public class NotificationEntityConfiguration : IEntityTypeConfiguration<NotificationEntity>
{
    public void Configure(EntityTypeBuilder<NotificationEntity> builder)
    {
        builder.ToTable("Notifications");
        builder.Property(x => x.Message).IsRequired().HasMaxLength(250);
        builder.Property(x => x.IsRead).IsRequired();
        builder.Property(x => x.CustomerName).IsRequired();
        builder.Property(x => x.Price).IsRequired();

        builder.HasOne(x => x.User).WithMany(x => x.Notifications).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.NoAction);

        BaseActivityConfiguration.Configure(builder);
    }
}