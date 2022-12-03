using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Events.UserPaymentVerification;

public class UserPaymentVerificationEvent : IEvent
{
    public UserPaymentVerificationEvent(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; private set; }
}
