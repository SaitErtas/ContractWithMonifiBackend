using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using MonifiBackend.Core.Infrastructure.Environments;
using System.Net;

namespace MonifiBackend.API.HealthCheck
{
    public class MyHealthCheck : IHealthCheck
    {
        private readonly ApplicationSettings _appSettings;
        private readonly Microsoft.AspNetCore.Hosting.IHostingEnvironment _hostingEnvironment;
        public MyHealthCheck(IOptions<ApplicationSettings> appSettings, Microsoft.AspNetCore.Hosting.IHostingEnvironment hostingEnvironment)
        {
            _hostingEnvironment = hostingEnvironment;
            _appSettings = appSettings.Value;
        }
        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            var catUrl = $"{_appSettings.ServiceAddress.BackendAddress}/api/Health";

            var client = new HttpClient();

            client.BaseAddress = new Uri(catUrl);

            HttpResponseMessage response = await client.GetAsync("");

            return response.StatusCode == HttpStatusCode.OK ?
                await Task.FromResult(new HealthCheckResult(
                      status: HealthStatus.Healthy,
                      description: "The API is healthy")) :
                await Task.FromResult(new HealthCheckResult(
                      status: HealthStatus.Unhealthy,
                      description: "The API is sick"));
        }
    }
}
