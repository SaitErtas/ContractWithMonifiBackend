using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Domain.Notifications;

public interface INotificationCommandDataPort : ICommandDataPort
{
    Task<bool> SaveAsync(Notification notification);
    Task SaveAsync(List<Notification> notifications);
}
