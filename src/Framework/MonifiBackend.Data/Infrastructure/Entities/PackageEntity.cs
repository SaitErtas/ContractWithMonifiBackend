using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class PackageEntity : BaseActivityEntity
{
    public string Name { get; set; }
    public int MinValue { get; set; }
    public int MaxValue { get; set; }
    public int ChangePeriodDay { get; set; }
    public int Bonus { get; set; }
    public string Icon { get; set; }
    public virtual ICollection<PackageDetailEntity> PackageDetails { get; set; }
}
public class PackageEntityConfiguration : IEntityTypeConfiguration<PackageEntity>
{
    public void Configure(EntityTypeBuilder<PackageEntity> builder)
    {
        builder.ToTable("Packages");
        builder.Property(x => x.Name).IsRequired().HasMaxLength(128);
        builder.Property(x => x.MinValue).IsRequired();
        builder.Property(x => x.MaxValue).IsRequired();
        builder.Property(x => x.ChangePeriodDay).IsRequired();
        builder.Property(x => x.Bonus).IsRequired();
        builder.Property(x => x.Icon).IsRequired();

        builder.HasMany(x => x.PackageDetails).WithOne(x => x.Package);

        BaseActivityConfiguration.Configure(builder);
    }
}
