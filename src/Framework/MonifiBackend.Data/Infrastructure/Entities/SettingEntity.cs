using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MonifiBackend.Data.Domain.Entities;
using MonifiBackend.Data.Domain.Entities.Configurations;

namespace MonifiBackend.Data.Infrastructure.Entities;

public class SettingEntity : BaseActivityEntity
{
    public string Name { get; set; }
    public long MaximumSalesQuantity { get; set; }
    public long MaximumDistributedAPY { get; set; }
    public long MaximumReferenceBonus { get; set; }
    public long TotalPreSaleQuantity { get; set; }
    public decimal MonifiPrice { get; set; }
    public string BscScanAddress { get; set; }
    public string TronNetworkAddress { get; set; }
    public string BscScanTokenSymbol { get; set; }
    public string TronNetworkTokenSymbol { get; set; }
    public bool MaintenanceMode { get; set; }

}
public class SettingEntityConfiguration : IEntityTypeConfiguration<SettingEntity>
{
    public void Configure(EntityTypeBuilder<SettingEntity> builder)
    {
        builder.ToTable("Settings");
        builder.Property(x => x.Name).IsRequired();
        builder.Property(x => x.MaximumSalesQuantity).IsRequired();
        builder.Property(x => x.MaximumDistributedAPY).IsRequired();
        builder.Property(x => x.MaximumReferenceBonus).IsRequired();
        builder.Property(x => x.TotalPreSaleQuantity).IsRequired();
        builder.Property(x => x.MonifiPrice).HasPrecision(9, 5).IsRequired();
        builder.Property(x => x.BscScanAddress).IsRequired();
        builder.Property(x => x.TronNetworkAddress).IsRequired();
        builder.Property(x => x.BscScanTokenSymbol).IsRequired();
        builder.Property(x => x.TronNetworkTokenSymbol).IsRequired();
        builder.Property(x => x.MaintenanceMode).IsRequired();

        BaseActivityConfiguration.Configure(builder);
    }
}