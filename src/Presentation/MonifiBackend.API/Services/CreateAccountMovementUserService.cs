using Microsoft.Extensions.Options;
using MonifiBackend.Core.Infrastructure.Environments;
using Sgbj.Cron;

namespace MonifiBackend.API.Services;

public class CreateAccountMovementUserService : BackgroundService
{
    private readonly ApplicationSettings _appSettings;
    private readonly Microsoft.AspNetCore.Hosting.IHostingEnvironment _hostingEnvironment;
    public CreateAccountMovementUserService(IOptions<ApplicationSettings> appSettings, Microsoft.AspNetCore.Hosting.IHostingEnvironment hostingEnvironment)
    {
        _hostingEnvironment = hostingEnvironment;
        _appSettings = appSettings.Value;
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // At minute 0
        using var timer = new CronTimer("*/5 * * * *");
        while (await timer.WaitForNextTickAsync())
        {
            try
            {
                var catUrl = $"{_appSettings.ServiceAddress.BackendAddress}/api/Wallets/add-movement";
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