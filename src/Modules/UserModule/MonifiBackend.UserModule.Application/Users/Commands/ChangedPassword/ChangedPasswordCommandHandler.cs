using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Domain.Users;
using System.Globalization;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("MonifiBackend.UserModule.UnitTests")]
[assembly: InternalsVisibleTo("MonifiBackend.UserModule.ArchTests")]
namespace MonifiBackend.UserModule.Application.Users.Commands.ChangedPassword;

internal class ChangedPasswordCommandHandler : ICommandHandler<ChangedPasswordCommand, ChangedPasswordCommandResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public ChangedPasswordCommandHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<ChangedPasswordCommandResponse> Handle(ChangedPasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetResetPasswordCodeAsync(request.ResetPasswordCode);
        AppRule.ExistsAndActive(user, new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])} ResetPasswordCode: {request.ResetPasswordCode}"));
        AppRule.True(user.ResetPasswordCode == request.ResetPasswordCode,
            new BusinessValidationException(
                $"{string.Format(_stringLocalizer["NotMach"], nameof(request.ResetPasswordCode))}",
                $"{string.Format(_stringLocalizer["NotMach"], nameof(request.ResetPasswordCode))} ResetPasswordCode: {request.ResetPasswordCode}, ResetPasswordCode: {request.ResetPasswordCode}")
            );

        string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);

        user.SetPassword(passwordHash);
        user.SetResetPasswordCode(string.Empty);


        Thread.CurrentThread.CurrentUICulture = new CultureInfo($"{user.Language.ShortName}");
        user.AddNotification($"{_stringLocalizer["ChangePassword"]}", user.FullName, default(decimal));

        var result = await _userCommandDataPort.SaveAsync(user);
        AppRule.True(result,
            new BusinessValidationException(
                $"{string.Format(_stringLocalizer["NotMach"], _stringLocalizer["User"])}",
                $"{string.Format(_stringLocalizer["NotMach"], _stringLocalizer["User"])} UserId: {user.Id}")
            );


        return new ChangedPasswordCommandResponse();
    }
}
