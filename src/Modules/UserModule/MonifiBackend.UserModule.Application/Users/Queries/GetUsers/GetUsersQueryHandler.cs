using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetUsers;

internal class GetUsersQueryHandler : IQueryHandler<GetUsersQuery, GetUsersQueryResponse>
{
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    private readonly IUserQueryDataPort _userQueryDataPort;
    public GetUsersQueryHandler(IUserQueryDataPort userQueryDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _stringLocalizer = stringLocalizer;
    }
    public async Task<GetUsersQueryResponse> Handle(GetUsersQuery request, CancellationToken cancellationToken)
    {
        var users = await _userQueryDataPort.GetAsync();
        return new GetUsersQueryResponse(users);
    }
}