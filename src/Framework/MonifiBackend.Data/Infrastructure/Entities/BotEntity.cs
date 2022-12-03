using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class BotEntity : BaseActivityEntity
{
    public int Hour { get; set; }
    public int Minute { get; set; }
    public int WorkingRange { get; set; }
    public int Range { get; set; }
    public int Amount { get; set; }
    public int PackageDetailId { get; set; }
}
public class BotEntityConfiguration : IEntityTypeConfiguration<BotEntity>
{
    public void Configure(EntityTypeBuilder<BotEntity> builder)
    {
        builder.ToTable("Bots");
        builder.Property(x => x.Hour).IsRequired();
        builder.Property(x => x.Minute).IsRequired();
        builder.Property(x => x.WorkingRange).IsRequired();
        builder.Property(x => x.Range).IsRequired();
        builder.Property(x => x.Amount).IsRequired();
        builder.Property(x => x.PackageDetailId).IsRequired();

        BaseActivityConfiguration.Configure(builder);
    }
}