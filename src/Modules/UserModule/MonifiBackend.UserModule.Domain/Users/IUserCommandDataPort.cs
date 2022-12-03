using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Domain.Users
{
    public interface IUserCommandDataPort : ICommandDataPort
    {
        Task<int> CreateAsync(User user);
        Task<bool> SaveAsync(User user);
        Task<bool> MarkAsReadAllNotificationAsync(int userId);
    }
}
