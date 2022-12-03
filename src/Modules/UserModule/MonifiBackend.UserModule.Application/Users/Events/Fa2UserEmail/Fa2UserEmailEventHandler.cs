using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Notifications;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Events.Fa2UserEmail;

internal class Fa2UserEmailEventHandler : IEventHandler<Fa2UserEmailEvent>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IEmailPort _emailPort;
    private readonly ApplicationSettings _appSettings;
    private readonly IHostingEnvironment _hostingEnvironment;
    public Fa2UserEmailEventHandler(IUserQueryDataPort userQueryDataPort, IEmailPort emailPort, IOptions<ApplicationSettings> appSettings, IHostingEnvironment hostingEnvironment)
    {
        _userQueryDataPort = userQueryDataPort;
        _emailPort = emailPort;
        _hostingEnvironment = hostingEnvironment;
        _appSettings = appSettings.Value;
    }
    public async Task Handle(Fa2UserEmailEvent request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        SendLoginMail(user, request.IpAddress);
    }
    private void SendLoginMail(User user, string ipAddress)
    {
        string filePath = Directory.GetCurrentDirectory() + "\\wwwroot\\Templates\\Fa2UserEmail.html";
        StreamReader str = new StreamReader(filePath);
        string mailText = str.ReadToEnd();
        str.Close();
        mailText = mailText.Replace("[Code]", $"{user.Fa2Code}").Replace("[LoginTime]", $"{DateTime.UtcNow.ToString("d")}");
        _emailPort.Send(user.Email, $"Monifi 2FA #{user.Fa2Code}", mailText);
    }
}