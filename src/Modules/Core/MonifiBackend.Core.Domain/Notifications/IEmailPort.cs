namespace MonifiBackend.Core.Domain.Notifications;

public interface IEmailPort
{
    void Send(string to, string subject, string html, string from = null);
}
