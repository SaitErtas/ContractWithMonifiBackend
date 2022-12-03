using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class VersionDetailEntity : BaseActivityEntity
{
    public int VersionId { get; set; }
    public string Name { get; set; }

    public virtual VersionEntity Version { get; set; }
}
public class VersionDetailEntityConfiguration : IEntityTypeConfiguration<VersionDetailEntity>
{
    public void Configure(EntityTypeBuilder<VersionDetailEntity> builder)
    {
        builder.ToTable("VersionDetails");
        builder.Property(x => x.Name).IsRequired().HasMaxLength(128);

        builder.HasOne(x => x.Version).WithMany(x => x.VersionDetails).HasForeignKey(x => x.VersionId).OnDelete(DeleteBehavior.NoAction);

        BaseActivityConfiguration.Configure(builder);
    }
}