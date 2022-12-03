using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Domain.Users;
using System.IdentityModel.Tokens.Jwt;

namespace MonifiBackend.UserModule.Application.Users.Commands.ConfirmUser;

internal class ConfirmUserCommandHandler : ICommandHandler<ConfirmUserCommand, ConfirmUserCommandResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IJwtUtils _jwtUtils;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public ConfirmUserCommandHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, IJwtUtils jwtUtils, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _jwtUtils = jwtUtils;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<ConfirmUserCommandResponse> Handle(ConfirmUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetUserConfirmationCodeAsync(request.ConfirmationCode);
        AppRule.Exists(user, new BusinessValidationException($"{string.Format(_stringLocalizer["NotMach"], _stringLocalizer["ConfirmationCode"])}", $"{string.Format(_stringLocalizer["NotMach"], _stringLocalizer["ConfirmationCode"])} ConfirmationCode: {request.ConfirmationCode}"));

        user.MarkAsActive();

        var status = await _userCommandDataPort.SaveAsync(user);
        AppRule.True<BusinessValidationException>(status);

        JwtSecurityToken jwtSecurityToken = await _jwtUtils.GenerateJwtToken(user);
        var jwtToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

        return new ConfirmUserCommandResponse(user, jwtToken);
    }
}
