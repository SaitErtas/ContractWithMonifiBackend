using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetNetworkUsers;

internal class GetNetworkUsersQueryHandler : IQueryHandler<GetNetworkUsersQuery, GetNetworkUsersQueryResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    public GetNetworkUsersQueryHandler(IUserQueryDataPort userQueryDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _stringLocalizer = stringLocalizer;
    }
    public async Task<GetNetworkUsersQueryResponse> Handle(GetNetworkUsersQuery request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        var lead = await _userQueryDataPort.GetAsync(user.ReferanceUser);
        var meFirstNetworkUsers = await _userQueryDataPort.GetMeFirstNetworkAsync(user.Id);

        var networkUserIds = meFirstNetworkUsers.Select(x => x.Id).ToList();
        var networkUsers = await _userQueryDataPort.GetAllNetworkAsync(networkUserIds);

        return new GetNetworkUsersQueryResponse(lead, meFirstNetworkUsers, networkUsers, _stringLocalizer);
    }
}