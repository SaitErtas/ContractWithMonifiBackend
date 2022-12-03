using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Notifications.Events.CreateNotification;

internal class CreateNotificationEventHandler : IEventHandler<CreateNotificationEvent>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    public CreateNotificationEventHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }
    public async Task Handle(CreateNotificationEvent request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);

        user.AddNotification(request.Message, request.CustomerName, request.Price);

        var result = await _userCommandDataPort.SaveAsync(user);
        AppRule.True(result, new BusinessValidationException($"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["User"])} UserId: {user.Id}"));
    }
}