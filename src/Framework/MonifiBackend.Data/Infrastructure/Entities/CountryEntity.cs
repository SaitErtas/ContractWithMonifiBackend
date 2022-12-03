using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class CountryEntity : BaseActivityEntity
{
    public string Name { get; set; }
    public string Flag { get; set; }
    public string Iso2 { get; set; }
    public string Iso3 { get; set; }
    public virtual ICollection<UserEntity> Users { get; set; }
}
public class CountryEntityConfiguration : IEntityTypeConfiguration<CountryEntity>
{
    public void Configure(EntityTypeBuilder<CountryEntity> builder)
    {
        builder.ToTable("Countries");
        builder.Property(x => x.Name).IsRequired().HasMaxLength(128);
        builder.Property(x => x.Flag).IsRequired().HasMaxLength(500);
        builder.Property(x => x.Iso2).IsRequired().HasMaxLength(128);
        builder.Property(x => x.Iso3).IsRequired().HasMaxLength(128);

        builder.HasMany(x => x.Users).WithOne(x => x.Country);

        BaseActivityConfiguration.Configure(builder);
    }
}