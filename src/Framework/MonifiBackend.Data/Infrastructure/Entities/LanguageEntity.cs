using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;
public class LanguageEntity : BaseActivityEntity
{
    public string Name { get; set; }
    public string NativeName { get; set; }
    public string ShortName { get; set; }
    public virtual ICollection<UserEntity> Users { get; set; }
}
public class LanguageEntityConfiguration : IEntityTypeConfiguration<LanguageEntity>
{
    public void Configure(EntityTypeBuilder<LanguageEntity> builder)
    {
        builder.ToTable("Languages");
        builder.Property(x => x.Name).IsRequired().HasMaxLength(250);
        builder.Property(x => x.NativeName).IsRequired().HasMaxLength(250);
        builder.Property(x => x.ShortName).IsRequired().HasMaxLength(128);

        builder.HasMany(x => x.Users).WithOne(x => x.Language);

        BaseActivityConfiguration.Configure(builder);
    }
}
