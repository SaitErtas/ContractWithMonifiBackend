using MediatR;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Application.Users.Events.Fa2UserEmail;
using MonifiBackend.UserModule.Domain.Users;
using System.Globalization;

namespace MonifiBackend.UserModule.Application.Users.Queries.AuthenticateUser;

internal class AuthenticateUserQueryHandler : IQueryHandler<AuthenticateUserQuery, AuthenticateUserQueryResponse>
{
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IJwtUtils _jwtUtils;
    private readonly IMediator _mediator;
    public AuthenticateUserQueryHandler(IUserCommandDataPort userCommandDataPort, IUserQueryDataPort userQueryDataPort, IJwtUtils jwtUtils, IStringLocalizer<Resource> stringLocalizer, IMediator mediator)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _jwtUtils = jwtUtils;
        _stringLocalizer = stringLocalizer;
        _mediator = mediator;
    }
    public async Task<AuthenticateUserQueryResponse> Handle(AuthenticateUserQuery request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetEmailAsync(request.Email);
        AppRule.Exists(user, new BusinessValidationException(string.Format(_stringLocalizer["NotFound"], request.Email), $"{string.Format(_stringLocalizer["NotFound"], request.Email)} Email: {request.Email}"));
        AppRule.False(user.Status == Core.Domain.Base.BaseStatus.Blocke, new BusinessValidationException(string.Format(_stringLocalizer["UserBloke"], request.Email), $"{string.Format(_stringLocalizer["UserBloke"], request.Email)} Email: {request.Email}"));
        AppRule.ExistsAndActive(user, new BusinessValidationException(string.Format(_stringLocalizer["NotActivetedUser"], request.Email), $"{string.Format(_stringLocalizer["NotActivetedUser"], request.Email)} Email: {request.Email}"));

        //var userPasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
        var verified = BCrypt.Net.BCrypt.Verify(request.Password, user.Password);
        AppRule.True(verified, new BusinessValidationException($"{_stringLocalizer["UserNotVerified"]}", $"{_stringLocalizer["UserNotVerified"]}. Email: {request.Email}"));

        user.AddUserIP(request.IpAddress, "Login");

        Thread.CurrentThread.CurrentUICulture = new CultureInfo($"{user.Language.ShortName}");
        user.AddNotification($"{string.Format(_stringLocalizer["LoginNotification"], DateTime.Now.ToString("d"), request.IpAddress)}", user.FullName, default(decimal));

        var fa2Code = await GenerateFa2Code();
        user.SetFa2Code(fa2Code);

        await _userCommandDataPort.SaveAsync(user);
        // authentication successful so generate jwt token
        //JwtSecurityToken jwtSecurityToken = await _jwtUtils.GenerateJwtToken(user);
        //var jwtToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

        //var loginUserEmailEvent = new LoginUserEmailEvent(user.Id, request.IpAddress);
        //await _mediator.Publish(loginUserEmailEvent);

        var fa2UserEmailEvent = new Fa2UserEmailEvent(user.Id, request.IpAddress);
        await _mediator.Publish(fa2UserEmailEvent);

        return new AuthenticateUserQueryResponse(user);
    }
    private async Task<string> GenerateFa2Code()
    {
        string fa2Code;
    TekrarOlustur:
        fa2Code = RandomKeyGenerator.RandomKey(6);
        //Böyle bir referans kodu var mı?
        var isFa2Code = await _userQueryDataPort.CheckUseFa2CodeAsync(fa2Code);
        if (!isFa2Code)
            return fa2Code;
        else
            goto TekrarOlustur;
    }
}
