using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Users.Phones;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region UserPhone to UserPhoneEntity 
    public static UserPhoneEntity Map(this UserPhone domain)
    {
        return new UserPhoneEntity()
        {
            Id = domain.Id,
            Number = domain.Number,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt
        };
    }
    #endregion
    #region UserPhoneEntity to UserPhone 
    public static UserPhone Map(this UserPhoneEntity entity)
    {
        if (entity == null)
            return UserPhone.Default();

        return UserPhone.Map(
                    entity.Id,
                    entity.Status.ToEnum<BaseStatus>(),
                    entity.Number,
                    entity.CreatedAt,
                    entity.ModifiedAt);
    }
    #endregion
}
