using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class NetworkEntity : BaseActivityEntity
{
    public string Name { get; set; }
    public virtual ICollection<WalletEntity> Wallets { get; set; }
}
public class NetworkEntityConfiguration : IEntityTypeConfiguration<NetworkEntity>
{
    public void Configure(EntityTypeBuilder<NetworkEntity> builder)
    {
        builder.ToTable("Networks");
        builder.Property(x => x.Name).IsRequired().HasMaxLength(250);

        builder.HasMany(x => x.Wallets).WithOne(x => x.CryptoNetwork);

        BaseActivityConfiguration.Configure(builder);
    }
}