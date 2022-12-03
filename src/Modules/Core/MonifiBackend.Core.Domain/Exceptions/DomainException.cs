namespace MonifiBackend.Core.Domain.Exceptions;

public class DomainException : BaseException
{
    private string _displayMessage;
    private string _excetionMessage;
    public DomainException(string displayMessage, string excetionMessage) : base()
    {
        _displayMessage = displayMessage;
        _excetionMessage = excetionMessage;
    }
    public DomainException(DomainExceptionMessageType messageType, string property, object value) : base()
    {
        _displayMessage = DomainExceptionMessages.SetMessage(messageType, property);
        _excetionMessage = DomainExceptionMessages.SetLogMessage(messageType, property, value.ToString());
    }
    public DomainException()
    {

    }
    public override string ExceptionId => "dbd35e2d-dc2d-4568-b415-4dcd291562c1";
    public override string DisplayMessage => $"{_displayMessage}";
    public override string Message => $"Domain Exception! {_excetionMessage}";
    public override int Status => 500;
}

public enum DomainExceptionMessageType
{
    NEGATIVE_OR_ZERO = 1,
    NULL_OR_EMPTY = 2
}
public static class DomainExceptionMessages
{
    public static readonly string NEGATIVE_OR_ZERO = "{0} Cannot Be Negative Or Zero.";
    public static readonly string LOG_NEGATIVE_OR_ZERO = "{0} Cannot Be Negative Or Zero. {0}: {1}";
    public static readonly string CANNOT_BE_NULL_OR_EMPTY = "{0} Cannot Be Null Or Empty.";
    public static readonly string LOG_CANNOT_BE_NULL_OR_EMPTY = "{0} Cannot Be Null Or Empty. {0}: {1}";
    public static string SetMessage(DomainExceptionMessageType messageType, string message)
    {
        switch (messageType)
        {
            case DomainExceptionMessageType.NEGATIVE_OR_ZERO:
                return string.Format(NEGATIVE_OR_ZERO, message);
            case DomainExceptionMessageType.NULL_OR_EMPTY:
                return string.Format(NEGATIVE_OR_ZERO, message);
        }
        throw new NotImplementedException();
    }
    public static string SetLogMessage(DomainExceptionMessageType messageType, string message, string value)
    {
        switch (messageType)
        {
            case DomainExceptionMessageType.NEGATIVE_OR_ZERO:
                return string.Format(LOG_NEGATIVE_OR_ZERO, message, value);
            case DomainExceptionMessageType.NULL_OR_EMPTY:
                return string.Format(LOG_CANNOT_BE_NULL_OR_EMPTY, message, value);
        }
        throw new NotImplementedException();
    }
}