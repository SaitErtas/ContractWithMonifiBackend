using MediatR;

namespace MonifiBackend.Core.Application.Abstractions
{
    public interface ICommandHandler<TCommand, TResult> : IRequestHandler<TCommand, TResult> where TCommand : ICommand<TResult> { }
}
