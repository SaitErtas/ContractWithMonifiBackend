using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Notifications.Events.CreateNotification;

public class CreateNotificationEvent : IEvent
{
    public CreateNotificationEvent(int userId, string message, string customerName, decimal price)
    {
        UserId = userId;
        Message = message;
        CustomerName = customerName;
        Price = price;
    }
    public int UserId { get; set; }
    public string Message { get; set; }
    public string CustomerName { get; set; }
    public decimal Price { get; set; }
}