using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Setting to SettingEntity 
    public static SettingEntity Map(this Setting domain)
    {
        if (domain == null)
            domain = Setting.Default();

        return new SettingEntity()
        {
            Id = domain.Id,
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            Status = domain.Status.ToInt(),
            Name = domain.Name,
            MaximumSalesQuantity = domain.MaximumSalesQuantity,
            MaximumDistributedAPY = domain.MaximumDistributedAPY,
            MaximumReferenceBonus = domain.MaximumReferenceBonus,
            TotalPreSaleQuantity = domain.TotalPreSaleQuantity,
            BscScanAddress = domain.BscScanAddress,
            TronNetworkAddress = domain.TronNetworkAddress,
            BscScanTokenSymbol = domain.BscScanTokenSymbol,
            TronNetworkTokenSymbol = domain.TronNetworkTokenSymbol,
        };
    }
    #endregion
    #region SettingEntity to Setting 
    public static Setting Map(this SettingEntity entity)
    {
        if (entity == null)
            return Setting.Default();

        return Setting.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Name,
            entity.MaximumSalesQuantity,
            entity.MaximumDistributedAPY,
            entity.MaximumReferenceBonus,
            entity.TotalPreSaleQuantity,
            entity.MonifiPrice,
            entity.MaintenanceMode,
            entity.BscScanAddress,
            entity.TronNetworkAddress,
            entity.BscScanTokenSymbol,
            entity.TronNetworkTokenSymbol);
    }
    #endregion
}