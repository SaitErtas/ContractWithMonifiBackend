using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Notifications.Commands.CreateNotification;

internal class CreateNotificationCommandHandler : ICommandHandler<CreateNotificationCommand, CreateNotificationCommandResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public CreateNotificationCommandHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<CreateNotificationCommandResponse> Handle(CreateNotificationCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        AppRule.ExistsAndActive(user, new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])} UserId: {request.UserId}"));

        user.AddNotification(request.Message, user.FullName, default(decimal));

        var result = await _userCommandDataPort.SaveAsync(user);
        AppRule.True(result, new BusinessValidationException($"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["User"])}. UserId: {user.Id}"));

        return new CreateNotificationCommandResponse();
    }
}