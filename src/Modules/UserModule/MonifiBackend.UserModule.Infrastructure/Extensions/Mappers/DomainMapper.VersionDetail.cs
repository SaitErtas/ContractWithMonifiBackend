using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Versions;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Version to VersionEntity 
    public static VersionDetailEntity Map(this VersionDetail domain)
    {
        return new VersionDetailEntity()
        {
            Id = domain.Id,
            Name = domain.Name,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
        };
    }
    #endregion
    #region VersionEntity to Version 
    public static VersionDetail Map(this VersionDetailEntity entity)
    {
        if (entity == null)
            return VersionDetail.Default();

        return VersionDetail.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Name);
    }
    #endregion
}