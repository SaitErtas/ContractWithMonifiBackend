using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Version to VersionEntity 
    public static VersionEntity Map(this Domain.Versions.Version domain)
    {
        var details = domain.Details != null ? domain.Details.Select(x => x.Map()).ToList() : null;

        return new VersionEntity()
        {
            Id = domain.Id,
            Name = domain.Name,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            VersionDetails = details
        };
    }
    #endregion
    #region VersionEntity to Version 
    public static Domain.Versions.Version Map(this VersionEntity entity)
    {
        if (entity == null)
            return Domain.Versions.Version.Default();

        return Domain.Versions.Version.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Name,
            entity.VersionDetails.Select(x => x.Map()).ToList());
    }
    #endregion
}