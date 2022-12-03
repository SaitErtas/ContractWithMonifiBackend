using MediatR;

namespace MonifiBackend.Core.Application.Abstractions
{
    public interface IEventHandler<TEvent> : INotificationHandler<TEvent> where TEvent : INotification { }
}
