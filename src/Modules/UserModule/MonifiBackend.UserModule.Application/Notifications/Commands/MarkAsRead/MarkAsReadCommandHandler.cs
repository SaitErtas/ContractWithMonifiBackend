using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Notifications.Commands.MarkAsRead;

internal class MarkAsReadCommandHandler : ICommandHandler<MarkAsReadCommand, MarkAsReadCommandResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public MarkAsReadCommandHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<MarkAsReadCommandResponse> Handle(MarkAsReadCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        AppRule.ExistsAndActive(user, new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])} UserId: {request.UserId}"));

        var result = await _userCommandDataPort.MarkAsReadAllNotificationAsync(request.UserId);
        AppRule.True(result, new BusinessValidationException($"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["User"])}. UserId: {user.Id}"));

        return new MarkAsReadCommandResponse();
    }
}