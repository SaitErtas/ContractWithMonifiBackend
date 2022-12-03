namespace MonifiBackend.Core.Domain.Base;

public enum TransactionStatus
{
    Successful = 1,
    Pending = 2,
    Fail = 3,
}

public class TransactionStatusStrings
{
    public const string SUCCESSFUL = "Successful";
    public const string PENDING = "Pending";
    public const string FAIL = "Fail";
}


