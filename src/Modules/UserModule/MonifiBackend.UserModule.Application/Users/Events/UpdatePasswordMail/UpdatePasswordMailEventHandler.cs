using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Notifications;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Events.UpdatePasswordMail;

internal class UpdatePasswordMailEventHandler : IEventHandler<UpdatePasswordMailEvent>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IEmailPort _emailPort;
    private readonly ApplicationSettings _appSettings;
    private readonly IHostingEnvironment _hostingEnvironment;
    public UpdatePasswordMailEventHandler(IUserQueryDataPort userQueryDataPort, IEmailPort emailPort, IOptions<ApplicationSettings> appSettings, IHostingEnvironment hostingEnvironment)
    {
        _userQueryDataPort = userQueryDataPort;
        _emailPort = emailPort;
        _hostingEnvironment = hostingEnvironment;
        _appSettings = appSettings.Value;
    }
    public async Task Handle(UpdatePasswordMailEvent request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        SendResetPasswordMail(user);
    }
    private void SendResetPasswordMail(User user)
    {
        var randomKey = RandomKeyGenerator.RandomKey(6);
        string filePath = Directory.GetCurrentDirectory() + "\\wwwroot\\Templates\\UpdatePassword.html";
        StreamReader str = new StreamReader(filePath);
        string mailText = str.ReadToEnd();
        str.Close();
        mailText = mailText.Replace("[PasswordAddress]", $"{_appSettings.ServiceAddress.FrontendAddress}/password-reset/{user.ResetPasswordCode}")
            .Replace("[PasswordCode]", $"{user.ResetPasswordCode}");
        _emailPort.Send(user.Email, $"Monofi.io Reset Password Email #{randomKey}", mailText);
    }
}