using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class PackageDetailEntity : BaseActivityEntity
{
    public int PackageId { get; set; }
    public string Name { get; set; }
    public int Duration { get; set; }
    public int Commission { get; set; }

    public virtual PackageEntity Package { get; set; }
    public virtual ICollection<AccountMovementEntity> AccountMovements { get; set; }
}
public class PackageDetailEntityConfiguration : IEntityTypeConfiguration<PackageDetailEntity>
{
    public void Configure(EntityTypeBuilder<PackageDetailEntity> builder)
    {
        builder.ToTable("PackageDetails");
        builder.Property(x => x.Name).IsRequired().HasMaxLength(128);
        builder.Property(x => x.Duration).IsRequired();
        builder.Property(x => x.Commission).IsRequired();

        builder.HasOne(x => x.Package).WithMany(x => x.PackageDetails).HasForeignKey(x => x.PackageId).OnDelete(DeleteBehavior.NoAction);
        builder.HasMany(x => x.AccountMovements).WithOne(x => x.PackageDetail);

        BaseActivityConfiguration.Configure(builder);
    }
}