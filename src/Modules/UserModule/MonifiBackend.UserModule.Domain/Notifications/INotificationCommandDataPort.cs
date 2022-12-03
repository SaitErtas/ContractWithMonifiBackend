using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Domain.Notifications;

public interface INotificationCommandDataPort : ICommandDataPort
{
    Task<bool> SaveAsync(Notification notification);
}
