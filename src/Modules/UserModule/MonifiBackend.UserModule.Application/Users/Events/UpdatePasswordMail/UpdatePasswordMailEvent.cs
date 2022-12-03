using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Users.Events.UpdatePasswordMail;

public class UpdatePasswordMailEvent : IEvent
{
    public UpdatePasswordMailEvent(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; set; }
}