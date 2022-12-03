using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class WalletEntity : BaseActivityEntity
{
    public int UserId { get; set; }
    public int CryptoNetworkId { get; set; }
    public string WalletAddress { get; set; }
    public virtual NetworkEntity CryptoNetwork { get; set; }
    public virtual UserEntity User { get; set; }
    public virtual ICollection<AccountMovementEntity> AccountMovements { get; set; }

}
public class WalletEntityConfiguration : IEntityTypeConfiguration<WalletEntity>
{
    public void Configure(EntityTypeBuilder<WalletEntity> builder)
    {
        builder.ToTable("Wallets");
        builder.Property(x => x.WalletAddress).IsRequired().HasMaxLength(250);

        builder.HasMany(x => x.AccountMovements).WithOne(x => x.Wallet);
        builder.HasOne(x => x.User).WithOne(x => x.Wallet).HasForeignKey<WalletEntity>(x => x.UserId).OnDelete(DeleteBehavior.NoAction);
        builder.HasOne(x => x.CryptoNetwork).WithMany(x => x.Wallets).HasForeignKey(x => x.CryptoNetworkId).OnDelete(DeleteBehavior.NoAction);

        BaseActivityConfiguration.Configure(builder);
    }
}