using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Users.Events.LoginUserEmail;

public class LoginUserEmailEvent : IEvent
{
    public LoginUserEmailEvent(int userId, string ipAddress)
    {
        UserId = userId;
        IpAddress = ipAddress;
    }
    public int UserId { get; set; }
    public string IpAddress { get; set; }
}