using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.WalletModule.Domain.AccountMovements;

namespace MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Network to NetworkEntity 
    public static NetworkEntity Map(this Network domain)
    {
        if (domain == null)
            domain = Network.Default();
        return new NetworkEntity()
        {
            Id = domain.Id,
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            Status = domain.Status.ToInt(),
            Name = domain.Name,
        };
    }
    #endregion
    #region NetworkEntity to Network 
    public static Network Map(this NetworkEntity entity)
    {
        if (entity == null)
            return Network.Default();

        return Network.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.Name,
            entity.CreatedAt,
            entity.ModifiedAt);
    }
    #endregion
}
