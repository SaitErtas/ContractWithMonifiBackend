using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Notifications;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Events.LoginUserEmail;

internal class LoginUserEmailEventHandler : IEventHandler<LoginUserEmailEvent>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IEmailPort _emailPort;
    private readonly ApplicationSettings _appSettings;
    private readonly IHostingEnvironment _hostingEnvironment;
    public LoginUserEmailEventHandler(IUserQueryDataPort userQueryDataPort, IEmailPort emailPort, IOptions<ApplicationSettings> appSettings, IHostingEnvironment hostingEnvironment)
    {
        _userQueryDataPort = userQueryDataPort;
        _emailPort = emailPort;
        _hostingEnvironment = hostingEnvironment;
        _appSettings = appSettings.Value;
    }
    public async Task Handle(LoginUserEmailEvent request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        SendLoginMail(user, request.IpAddress);
    }
    private void SendLoginMail(User user, string ipAddress)
    {
        var randomKey = RandomKeyGenerator.RandomKey(6);
        string filePath = Directory.GetCurrentDirectory() + "\\wwwroot\\Templates\\LoginEmail.html";
        StreamReader str = new StreamReader(filePath);
        string mailText = str.ReadToEnd();
        str.Close();
        mailText = mailText.Replace("[IpAddress]", $"{ipAddress}").Replace("[LoginTime]", $"{DateTime.UtcNow.ToString("d")}");
        _emailPort.Send(user.Email, $"Monifi Login Alert #{randomKey}", mailText);
    }
}