using MediatR;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Application.Users.Events.LoginUserEmail;
using MonifiBackend.UserModule.Domain.Users;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;

namespace MonifiBackend.UserModule.Application.Users.Commands.Fa2Auth;

internal class Fa2AuthCommandHandler : ICommandHandler<Fa2AuthCommand, Fa2AuthCommandResponse>
{
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IJwtUtils _jwtUtils;
    private readonly IMediator _mediator;
    public Fa2AuthCommandHandler(IUserCommandDataPort userCommandDataPort, IUserQueryDataPort userQueryDataPort, IJwtUtils jwtUtils, IStringLocalizer<Resource> stringLocalizer, IMediator mediator)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _jwtUtils = jwtUtils;
        _stringLocalizer = stringLocalizer;
        _mediator = mediator;
    }

    public async Task<Fa2AuthCommandResponse> Handle(Fa2AuthCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetEmailAsync(request.Email);
        AppRule.Exists(user, new BusinessValidationException(string.Format(_stringLocalizer["NotFound"], request.Email), $"{string.Format(_stringLocalizer["NotFound"], request.Email)} Email: {request.Email}"));
        AppRule.False(user.Status == Core.Domain.Base.BaseStatus.Blocke, new BusinessValidationException(string.Format(_stringLocalizer["UserBloke"], request.Email), $"{string.Format(_stringLocalizer["UserBloke"], request.Email)} Email: {request.Email}"));
        AppRule.ExistsAndActive(user, new BusinessValidationException(string.Format(_stringLocalizer["NotActivetedUser"], request.Email), $"{string.Format(_stringLocalizer["NotActivetedUser"], request.Email)} Email: {request.Email}"));

        user.AddUserIP(request.IpAddress, "Fa2Auth");

        Thread.CurrentThread.CurrentUICulture = new CultureInfo($"{user.Language.ShortName}");
        user.AddNotification($"{string.Format(_stringLocalizer["LoginNotification"], DateTime.Now.ToString("d"), request.IpAddress)}", user.FullName, default(decimal));

        user.SetFa2Code(string.Empty);

        await _userCommandDataPort.SaveAsync(user);
        // authentication successful so generate jwt token
        JwtSecurityToken jwtSecurityToken = await _jwtUtils.GenerateJwtToken(user);
        var jwtToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

        var loginUserEmailEvent = new LoginUserEmailEvent(user.Id, request.IpAddress);
        await _mediator.Publish(loginUserEmailEvent);

        return new Fa2AuthCommandResponse(user, jwtToken);
    }
    private async Task<string> GenerateReferanceCode()
    {
        string referanceCode;
    TekrarOlustur:
        referanceCode = RandomKeyGenerator.RandomKey(6);
        //Böyle bir referans kodu var mı?
        var isReferanceCode = await _userQueryDataPort.CheckUserReferanceCodeAsync(referanceCode);
        if (!isReferanceCode)
            return referanceCode;
        else
            goto TekrarOlustur;
    }
    private async Task<string> GenerateConfirmationCode()
    {
        string confirmationCode;
    TekrarOlustur:
        confirmationCode = RandomKeyGenerator.RandomKey(6);
        //Böyle bir referans kodu var mı?
        var isConfirmationCode = await _userQueryDataPort.CheckUserConfirmationCodeAsync(confirmationCode);
        if (!isConfirmationCode)
            return confirmationCode;
        else
            goto TekrarOlustur;
    }
}