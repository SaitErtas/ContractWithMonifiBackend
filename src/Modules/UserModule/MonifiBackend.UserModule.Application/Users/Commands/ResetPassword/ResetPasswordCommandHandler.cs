using MediatR;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.UserModule.Application.Users.Events.ResetPasswordMail;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Commands.ResetPassword;

internal class ResetPasswordCommandHandler : ICommandHandler<ResetPasswordCommand, ResetPasswordCommandResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IMediator _mediator;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public ResetPasswordCommandHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, IMediator mediator, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _mediator = mediator;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<ResetPasswordCommandResponse> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetEmailAsync(request.Email);
        AppRule.Exists(user, new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])} Email: {request.Email}"));

        var resetPasswordCode = await GenerateResetPasswordCode();
        user.SetResetPasswordCode(resetPasswordCode);

        var result = await _userCommandDataPort.SaveAsync(user);
        AppRule.True(result, new BusinessValidationException($"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["User"])} UserId: {user.Id}"));

        var registerComplitedEvent = new ResetPasswordMailEvent(user.Id);
        await _mediator.Publish(registerComplitedEvent);

        return new ResetPasswordCommandResponse();
    }
    private async Task<string> GenerateResetPasswordCode()
    {
        string resetPasswordCode;
    TekrarOlustur:
        resetPasswordCode = RandomKeyGenerator.RandomKey(6);
        //Böyle bir referans kodu var mı?
        var isResetPasswordCode = await _userQueryDataPort.CheckUserResetPasswordCodeAsync(resetPasswordCode);
        if (!isResetPasswordCode)
            return resetPasswordCode;
        else
            goto TekrarOlustur;
    }
}
