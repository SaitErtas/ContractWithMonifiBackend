using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Notifications;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

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
}
