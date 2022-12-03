using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Users.Events.ResetPasswordMail;

public class ResetPasswordMailEvent : IEvent
{
    public ResetPasswordMailEvent(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; set; }
}