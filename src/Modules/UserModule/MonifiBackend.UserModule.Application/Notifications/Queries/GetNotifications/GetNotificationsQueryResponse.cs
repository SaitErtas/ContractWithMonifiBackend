using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.UserModule.Domain.Users.Notifications;

namespace MonifiBackend.UserModule.Application.Notifications.Queries.GetNotifications;

public class GetNotificationsQueryResponse
{
    public GetNotificationsQueryResponse(List<UserNotification> notifications, User user)
    {
        Notifications = notifications.Select(x => new GetNotificationQuery(x, user)).ToList();
    }
    public List<GetNotificationQuery> Notifications { get; set; }
}
public class GetNotificationQuery
{
    public GetNotificationQuery(UserNotification notification, User user)
    {

        Message = notification.Message;
        IsRead = notification.IsRead;
        Id = notification.Id;
        CustomerName = notification.CustomerName == user.FullName ? null : notification.CustomerName.CapitalizeFirstAndHideText(2);
        Price = notification.Price == default(decimal) ? null : notification.Price;
        CreatedAt = notification.CreatedAt;
        Color = RandText();
    }

    private string RandText()
    {
        Random rnd = new Random();
        var number = rnd.Next(0, 5);

        var colors = new List<string>();
        colors.Add("primary");
        colors.Add("secondary");
        colors.Add("error");
        colors.Add("warning");
        colors.Add("info");
        colors.Add("success");
        return colors[number].ToString();
    }

    public string Message { get; set; }
    public bool IsRead { get; set; }
    public int Id { get; set; }
    public string CustomerName { get; set; }
    public decimal? Price { get; set; }
    public DateTime CreatedAt { get; set; }
    public string Color { get; set; }
}