namespace MonifiBackend.Core.Domain.Exceptions;

public class BusinessValidationException : BaseException
{
    private string _displayMessage;
    private string _excetionMessage;
    public BusinessValidationException(string displayMessage, string excetionMessage) : base()
    {
        _displayMessage = displayMessage;
        _excetionMessage = excetionMessage;
    }
    public BusinessValidationException(BusinessValidationMessageType messageType, string property, object value) : base()
    {
        _displayMessage = BusinessValidationExceptionMessages.SetMessage(messageType, property);
        _excetionMessage = BusinessValidationExceptionMessages.SetLogMessage(messageType, property, value.ToString());
    }
    public override string ExceptionId => "59caf220-9308-4a63-86d9-281f5bd88f64";
    public override string DisplayMessage => $"{_displayMessage}";
    public override string Message => $"Business Exception! {_excetionMessage}";
    public override int Status => 500;
}
public enum BusinessValidationMessageType
{
    ALREADY_EXIST = 1,
    NOT_CREATED = 2,
    NOT_UPDATED = 3,
    NOT_FOUND = 4
}
public static class BusinessValidationExceptionMessages
{
    public static readonly string ALREADY_EXIST = "{0} already exist.";
    public static readonly string NOT_CREATED = "{0} not created.";
    public static readonly string NOT_UPDATED = "{0} not updated.";
    public static readonly string NOT_FOUND = "{0} not found.";

    public static readonly string LOG_NEGATIVE_OR_ZERO = "{0} already exist. {0}: {1}";
    public static readonly string LOG_ALREADY_EXIST = "{0} already exist. {0}: {1}";
    public static readonly string LOG_NOT_CREATED = "{0} not created. {0}: {1}";
    public static readonly string LOG_NOT_UPDATED = "{0} not updated. {0}: {1}";
    public static readonly string LOG_NOT_FOUND = "{0} not found. {0}: {1}";
    public static string SetMessage(BusinessValidationMessageType messageType, string message)
    {
        switch (messageType)
        {
            case BusinessValidationMessageType.ALREADY_EXIST:
                return string.Format(ALREADY_EXIST, message);
            case BusinessValidationMessageType.NOT_CREATED:
                return string.Format(NOT_CREATED, message);
            case BusinessValidationMessageType.NOT_UPDATED:
                return string.Format(NOT_UPDATED, message);
            case BusinessValidationMessageType.NOT_FOUND:
                return string.Format(NOT_FOUND, message);
        }
        throw new NotImplementedException();
    }
    public static string SetLogMessage(BusinessValidationMessageType messageType, string message, string value)
    {
        switch (messageType)
        {
            case BusinessValidationMessageType.ALREADY_EXIST:
                return string.Format(LOG_ALREADY_EXIST, message, value);
            case BusinessValidationMessageType.NOT_CREATED:
                return string.Format(LOG_NOT_CREATED, message, value);
            case BusinessValidationMessageType.NOT_UPDATED:
                return string.Format(LOG_NOT_UPDATED, message, value);
            case BusinessValidationMessageType.NOT_FOUND:
                return string.Format(LOG_NOT_FOUND, message, value);
        }
        throw new NotImplementedException();
    }
}
