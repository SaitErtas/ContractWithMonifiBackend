using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Users.Notifications;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region UserNotification to NotificationEntity 
    public static NotificationEntity Map(this UserNotification domain)
    {
        return new NotificationEntity()
        {
            Id = domain.Id,
            Message = domain.Message,
            IsRead = domain.IsRead,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            CustomerName = domain.CustomerName,
            Price = domain.Price,
        };
    }
    #endregion
    #region NotificationEntity to UserNotification 
    public static UserNotification Map(this NotificationEntity entity)
    {
        if (entity == null)
            return UserNotification.Default();

        return UserNotification.Map(
                    entity.Id,
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