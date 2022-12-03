using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region UserIP to UserIPEntity 
    public static UserIPEntity Map(this UserIP domain)
    {
        return new UserIPEntity()
        {
            Id = domain.Id,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            IpAddress = domain.IpAddress,
            RequestName = domain.RequestName,
        };
    }
    #endregion
    #region UserIPEntity to UserIP 
    public static UserIP Map(this UserIPEntity entity)
    {
        if (entity == null)
            return UserIP.Default();

        return UserIP.Map(
                    entity.Id,
                    entity.Status.ToEnum<BaseStatus>(),
                    entity.CreatedAt,
                    entity.ModifiedAt,
                    entity.IpAddress,
                    entity.RequestName);
    }
    #endregion
}