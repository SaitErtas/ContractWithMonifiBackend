using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.WalletModule.Domain.Packages;

namespace MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Package to PackageEntity 
    public static PackageEntity Map(this Package domain)
    {
        var details = domain.Details != null ? domain.Details.Select(x => x.Map()).ToList() : null;

        return new PackageEntity()
        {
            Id = domain.Id,
            Name = domain.Name,
            Status = domain.Status.ToInt(),
            Bonus = domain.Bonus,
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            PackageDetails = details
        };
    }
    #endregion
    #region PackageEntity to Package 
    public static Package Map(this PackageEntity entity)
    {
        if (entity == null)
            return Package.Default();


        return Package.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Name,
            entity.MinValue,
            entity.MaxValue,
            entity.ChangePeriodDay,
            entity.Bonus,
            entity.PackageDetails.Select(x => x.Map()).ToList());
    }
    #endregion
    #region PackageEntity to Package 
    public static Package MapNotPackageDetail(this PackageEntity entity)
    {
        if (entity == null)
            return Package.Default();


        return Package.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Name,
            entity.MinValue,
            entity.MaxValue,
            entity.ChangePeriodDay,
            entity.Bonus);
    }
    #endregion
}
