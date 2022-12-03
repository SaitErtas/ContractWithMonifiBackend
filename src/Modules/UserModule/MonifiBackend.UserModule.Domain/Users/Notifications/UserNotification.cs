using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;

namespace MonifiBackend.UserModule.Domain.Users.Notifications;

public sealed class UserNotification : BaseActivityDomain<int>
{
    private UserNotification() { }
    public string Message { get; private set; }
    public bool IsRead { get; private set; }
    public string CustomerName { get; private set; }
    public decimal Price { get; private set; }
    public static UserNotification CreateNew(string message, string customerName, decimal price)
    {
        AppRule.NotNullOrEmpty<DomainException>(message, "Message not null or empty", $"Message not null or empty. Message: {message}");

        return new UserNotification()
        {
            Message = message,
            IsRead = false,
            CustomerName = customerName,
            Price = price
        };
    }

    public static UserNotification Default() => new();

    public static UserNotification Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string message,
        bool isRead,
        string customerName,
        decimal price)
    {
        return new UserNotification()
        {
            Id = id,
            Status = status,
            Message = message,
            IsRead = isRead,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            CustomerName = customerName,
            Price = price
        };
    }
}