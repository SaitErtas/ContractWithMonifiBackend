namespace MonifiBackend.Core.Domain.Base;

public enum ActionType
{
    Sale = 1,
    Refund = 2,
    Void = 3,
    Bonus = 4,
}
public class ActionTypeStrings
{
    public const string SALE = "Sale";
    public const string REFUND = "Refund";
    public const string VOID = "Void";
    public const string BONUS = "Bonus";
}

