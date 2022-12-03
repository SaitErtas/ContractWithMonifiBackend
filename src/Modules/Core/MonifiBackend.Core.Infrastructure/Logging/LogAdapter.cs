using Microsoft.Extensions.Logging;
using MonifiBackend.Core.Domain.Logging;

namespace MonifiBackend.Core.Infrastructure.Logging
{
    public class LogAdapter : ILogPort
    {
        public ILogger<LogAdapter> _logger;
        public LogAdapter(ILogger<LogAdapter> logger)
        {
            _logger = logger;
        }

        public void LogError(string message) => _logger.LogError(message);
        public void LogError(string message, Exception ex) => _logger.LogError(message, ex);

        public void LogInfo(string message) { }
        public void LogInfo(string message, Exception ex) { }

        public void LogWarn(string message) => _logger.LogWarning(message);
        public void LogWarn(string message, Exception ex) => _logger.LogWarning(message, ex);
    }
}
