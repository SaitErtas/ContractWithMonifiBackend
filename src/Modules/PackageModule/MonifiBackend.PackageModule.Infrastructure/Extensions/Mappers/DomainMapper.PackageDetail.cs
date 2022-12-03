using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.PackageDetailModule.Domain.PackageDetails;

namespace MonifiBackend.PackageModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Package to PackageEntity 
    public static PackageDetailEntity Map(this PackageDetail domain)
    {
        return new PackageDetailEntity()
        {
            Id = domain.Id,
            Name = domain.Name,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            Commission = domain.Commission,
            Duration = domain.Duration,
        };
    }
    #endregion
    #region PackageEntity to Package 
    public static PackageDetail Map(this PackageDetailEntity entity)
    {
        if (entity == null)
            return PackageDetail.Default();

        return PackageDetail.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Name,
            entity.Duration,
            entity.Commission);
    }
    #endregion
}
