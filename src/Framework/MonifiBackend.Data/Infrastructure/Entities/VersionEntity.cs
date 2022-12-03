using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class VersionEntity : BaseActivityEntity
{
    public string Name { get; set; }
    public virtual ICollection<VersionDetailEntity> VersionDetails { get; set; }
}
public class VersionEntityConfiguration : IEntityTypeConfiguration<VersionEntity>
{
    public void Configure(EntityTypeBuilder<VersionEntity> builder)
    {
        builder.ToTable("Versions");
        builder.Property(x => x.Name).IsRequired().HasMaxLength(128);

        builder.HasMany(x => x.VersionDetails).WithOne(x => x.Version);

        BaseActivityConfiguration.Configure(builder);
    }
}