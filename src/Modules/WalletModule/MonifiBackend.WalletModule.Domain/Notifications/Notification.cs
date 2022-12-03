using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;

namespace MonifiBackend.WalletModule.Domain.Notifications;

public sealed class Notification : BaseActivityDomain<int>
{
    private Notification() { }
    public int UserId { get; private set; }
    public string Message { get; private set; }
    public bool IsRead { get; private set; }
    public string CustomerName { get; private set; }
    public decimal Price { get; private set; }
    public static Notification CreateNew(int userId, string message, string customerName, decimal price)
    {
        AppRule.NotNegativeOrZero<DomainException>(userId, "UserId not null or empty", $"UserId not null or empty. Message: {message}");
        AppRule.NotNullOrEmpty<DomainException>(message, "Message not null or empty", $"Message not null or empty. Message: {message}");

        return new Notification()
        {
            UserId = userId,
            Message = message,
            IsRead = false,
            CustomerName = customerName,
            Price = price
        };
    }

    public static Notification Default() => new();

    public static Notification Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string message,
        bool isRead,
        string customerName,
        decimal price)
    {
        return new Notification()
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
