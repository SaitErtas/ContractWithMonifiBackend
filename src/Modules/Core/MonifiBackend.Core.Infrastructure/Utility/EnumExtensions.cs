using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.Core.Infrastructure.Utility;

public static class TransactionStatusExtensions
{
    public static string ToTransactionStatus(this TransactionStatus status, IStringLocalizer<Resource> stringLocalizer)
    {
        return status switch
        {
            TransactionStatus.Successful => stringLocalizer["Successful"],
            TransactionStatus.Pending => stringLocalizer["Pending"],
            TransactionStatus.Fail => stringLocalizer["Fail"],
            _ => throw new NotImplementedException()
        };
    }
    public static string ToTransactionStatusColor(this TransactionStatus status)
    {
        return status switch
        {
            TransactionStatus.Successful => "success",
            TransactionStatus.Pending => "info",
            TransactionStatus.Fail => "error",
            _ => throw new NotImplementedException()
        };
    }
    public static string ToTransactionStatusDescription(this TransactionStatus status, IStringLocalizer<Resource> stringLocalizer)
    {
        return status switch
        {
            TransactionStatus.Successful => stringLocalizer["TransactionStatusSuccessful"],
            TransactionStatus.Pending => stringLocalizer["TransactionStatusPending"],
            TransactionStatus.Fail => stringLocalizer["TransactionStatusFail"],
            _ => throw new NotImplementedException()
        };
    }
}
public static class ActionTypeExtensions
{
    public static string ToActionType(this ActionType status, IStringLocalizer<Resource> stringLocalizer)
    {
        return status switch
        {
            ActionType.Sale => stringLocalizer["Sale"],
            ActionType.Refund => stringLocalizer["Refund"],
            ActionType.Void => stringLocalizer["Void"],
            ActionType.Bonus => stringLocalizer["Bonus"],
            _ => throw new NotImplementedException()
        };
    }
}
public static class BaseStatusExtensions
{
    public static string ToBaseStatus(this BaseStatus status, IStringLocalizer<Resource> stringLocalizer)
    {
        return status switch
        {
            BaseStatus.Active => stringLocalizer["Active"],
            BaseStatus.Passive => stringLocalizer["Passive"],
            BaseStatus.Deleted => stringLocalizer["Deleted"],
            _ => throw new NotImplementedException()
        };
    }
}