using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.UserModule.Domain.Notifications;
using MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.UserModule.Infrastructure.Notifications;

public class NotificationCommandDataAdapter : INotificationCommandDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public NotificationCommandDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }
    public async Task<bool> SaveAsync(Notification notification)
    {
        _dbContext.Notifications.Update(notification.Map());
        return (await _dbContext.SaveChangesAsync()) > 0;
    }
}
