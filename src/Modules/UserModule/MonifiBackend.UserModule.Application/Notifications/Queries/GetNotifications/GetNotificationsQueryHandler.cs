using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Notifications.Queries.GetNotifications;

internal class GetNotificationsQueryHandler : IQueryHandler<GetNotificationsQuery, GetNotificationsQueryResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IJwtUtils _jwtUtils;
    public GetNotificationsQueryHandler(IUserQueryDataPort userQueryDataPort, IJwtUtils jwtUtils)
    {
        _userQueryDataPort = userQueryDataPort;
        _jwtUtils = jwtUtils;
    }
    public async Task<GetNotificationsQueryResponse> Handle(GetNotificationsQuery request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        var notifications = await _userQueryDataPort.GetNotificationsAsync(request.UserId);

        return new GetNotificationsQueryResponse(notifications, user);
    }
}