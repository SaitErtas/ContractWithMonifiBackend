using MediatR;

namespace MonifiBackend.Core.Application.Abstractions
{
    public interface IQuery<TResponse> : IRequest<TResponse> { }
}
