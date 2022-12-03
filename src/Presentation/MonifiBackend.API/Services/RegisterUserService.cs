using Microsoft.Extensions.Options;
using MonifiBackend.Core.Infrastructure.Environments;
using Sgbj.Cron;

namespace MonifiBackend.API.Services;

public class RegisterUserService : BackgroundService
{
    private readonly ApplicationSettings _appSettings;
    private readonly Microsoft.AspNetCore.Hosting.IHostingEnvironment _hostingEnvironment;
    public RegisterUserService(IOptions<ApplicationSettings> appSettings, Microsoft.AspNetCore.Hosting.IHostingEnvironment hostingEnvironment)
    {
        _hostingEnvironment = hostingEnvironment;
        _appSettings = appSettings.Value;
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // At minute 0
        using var timer = new CronTimer("*/27 * * * *");
        while (await timer.WaitForNextTickAsync())
        {
            try
            {
                var catUrl = $"{_appSettings.ServiceAddress.BackendAddress}/api/Users/register-add-user-event";
                var client = new HttpClient();
                client.BaseAddress = new Uri(catUrl);
                HttpResponseMessage response = await client.GetAsync("");
            }
            catch (Exception e)
            {

            }
        }
        await Task.CompletedTask;
    }
}