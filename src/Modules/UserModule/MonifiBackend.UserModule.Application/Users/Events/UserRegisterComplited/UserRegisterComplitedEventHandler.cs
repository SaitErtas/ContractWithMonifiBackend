using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Notifications;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Events.UserRegisterComplited;

internal class UserRegisterComplitedEventHandler : IEventHandler<UserRegisterComplitedEvent>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IEmailPort _emailPort;
    private readonly ApplicationSettings _appSettings;
    private readonly IHostingEnvironment _hostingEnvironment;
    public UserRegisterComplitedEventHandler(IUserQueryDataPort userQueryDataPort, IEmailPort emailPort, IOptions<ApplicationSettings> appSettings, IHostingEnvironment hostingEnvironment)
    {
        _userQueryDataPort = userQueryDataPort;
        _emailPort = emailPort;
        _hostingEnvironment = hostingEnvironment;
        _appSettings = appSettings.Value;
    }
    public async Task Handle(UserRegisterComplitedEvent request, CancellationToken cancellationToken)
    {
        //GetUser
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        SendVerificationMail(user);
    }
    private void SendVerificationMail(User user)
    {
        var randomKey = RandomKeyGenerator.RandomKey(6);
        string filePath = Directory.GetCurrentDirectory() + "\\wwwroot\\Templates\\VerificationMail.html";
        StreamReader str = new StreamReader(filePath);
        string mailText = str.ReadToEnd();
        str.Close();
        mailText = mailText.Replace("[VerificationAddress]", $"{_appSettings.ServiceAddress.FrontendAddress}/account-confirmation/{user.ConfirmationCode}");
        mailText = mailText.Replace("[PrivacyPolicyTerms]", $"{_appSettings.ServiceAddress.FrontendAddress}/privacy-policy");

        _emailPort.Send(user.Email, $"Monofi.io Verification Email #{randomKey}", mailText);
    }
}