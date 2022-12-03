using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Users.Events.UserRegisterComplited;

public class UserRegisterComplitedEvent : IEvent
{
    public UserRegisterComplitedEvent(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; set; }
}