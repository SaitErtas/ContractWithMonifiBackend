using MediatR;

namespace MonifiBackend.Core.Application.Abstractions
{
    public interface ICommand<TResult> : IRequest<TResult> { }
}
