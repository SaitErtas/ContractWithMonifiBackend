using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.Notifications;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.Notifications;

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
    public async Task SaveAsync(List<Notification> notifications)
    {
        _dbContext.Notifications.UpdateRange(notifications.Select(x => x.Map()).ToList());
        await _dbContext.SaveChangesAsync();
    }
}