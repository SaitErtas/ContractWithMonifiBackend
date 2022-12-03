using MediatR;
using MonifiBackend.Core.Domain.Logging;
using System.Reflection;

namespace MonifiBackend.Core.Infrastructure.Middlewares
{
    public class LoggingBehaviour<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse> where TRequest : IRequest<TResponse>
    {
        private readonly ILogPort _logPort;
        public LoggingBehaviour(ILogPort logPort)
        {
            _logPort = logPort;
        }
        public async Task<TResponse> Handle(TRequest request, CancellationToken cancellationToken, RequestHandlerDelegate<TResponse> next)
        {
            //Request
            _logPort.LogInfo($"Handling {typeof(TRequest).Name}");
            Type myType = request.GetType();
            IList<PropertyInfo> props = new List<PropertyInfo>(myType.GetProperties());
            foreach (PropertyInfo prop in props)
            {
                object propValue = prop.GetValue(request, null);
                _logPort.LogInfo($"{prop.Name} : {propValue}");
            }
            var response = await next();
            //Response
            _logPort.LogInfo($"Handled {typeof(TResponse).Name}");
            return response;
        }
    }
}
