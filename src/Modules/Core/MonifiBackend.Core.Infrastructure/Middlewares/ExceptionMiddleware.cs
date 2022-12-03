using Microsoft.AspNetCore.Http;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Logging;
using MonifiBackend.Core.Domain.Responses;
using System.Text.Json;

namespace MonifiBackend.Core.Infrastructure.Middlewares
{
    public class ExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogPort _logPort;
        public ExceptionMiddleware(RequestDelegate next, ILogPort logPort)
        {
            _logPort = logPort;
            _next = next;
        }
        public async Task InvokeAsync(HttpContext httpContext)
        {
            try
            {
                await _next(httpContext);
            }
            catch (Exception exception)
            {
                var response = httpContext.Response;
                response.ContentType = "application/json";

                var appResponse = default(ResponseWrapper<object>);
                var errors = default(IEnumerable<string>);

                if (exception is BaseException baseException)
                {
                    _logPort.LogError($"{baseException.Message}", exception);
                    appResponse = new ResponseWrapper<object>(baseException.Status, baseException.ExceptionId, baseException.DisplayMessage);
                }
                else if (exception is FluentValidation.ValidationException validationException)
                {
                    errors = validationException.Errors.Select(x => x.ErrorMessage).ToList();
                    appResponse = new ResponseWrapper<object>(400, "VAL-101", errors);
                }
                else
                {
                    _logPort.LogError($"{exception.Message}", exception);
                    appResponse = new ResponseWrapper<object>(500, "SYS-101", exception.Message);
                }

                response.StatusCode = appResponse.StatusCode;
                var json = JsonSerializer.Serialize(appResponse);
                await response.WriteAsync(json);
            }
        }
    }
}
