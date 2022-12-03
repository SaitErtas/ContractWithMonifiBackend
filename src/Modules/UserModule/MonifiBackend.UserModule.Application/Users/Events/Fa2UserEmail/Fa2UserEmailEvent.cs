using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Users.Events.Fa2UserEmail;

public class Fa2UserEmailEvent : IEvent
{
    public Fa2UserEmailEvent(int userId, string ipAddress)
    {
        UserId = userId;
        IpAddress = ipAddress;
    }
    public int UserId { get; set; }
    public string IpAddress { get; set; }
}