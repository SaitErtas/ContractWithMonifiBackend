using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.WalletModule.Domain.Notifications;

namespace MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Notification to NotificationEntity 
    public static NotificationEntity Map(this Notification domain)
    {
        return new NotificationEntity()
        {
            Id = domain.Id,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            UserId = domain.UserId,
            IsRead = domain.IsRead,
            Message = domain.Message,
            CustomerName = domain.CustomerName,
            Price = domain.Price,
        };
    }
    #endregion
    #region NotificationEntity to Notification 
    public static Notification Map(this NotificationEntity entity)
    {
        if (entity == null)
            return Notification.Default();

        return Notification.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Message,
            entity.IsRead,
            entity.CustomerName,
            entity.Price);
    }
    #endregion
}