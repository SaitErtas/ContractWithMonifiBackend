using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetOrganizationalCharts;

internal class GetOrganizationalChartQueryHandler : IQueryHandler<GetOrganizationalChartQuery, GetOrganizationalChartQueryResponse>
{
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    private readonly IUserQueryDataPort _userQueryDataPort;
    public GetOrganizationalChartQueryHandler(IUserQueryDataPort userQueryDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _userQueryDataPort = userQueryDataPort;
        _stringLocalizer = stringLocalizer;
    }
    public async Task<GetOrganizationalChartQueryResponse> Handle(GetOrganizationalChartQuery request, CancellationToken cancellationToken)
    {
        var allUsers = await _userQueryDataPort.GetAsync();
        var users = new List<User>();
        int parentUserId = 0;

        //userId tespit ediliyor.
        if (request.UserId > 0)
        {
            parentUserId = allUsers.Where(p => p.Id == request.UserId).FirstOrDefault().ReferanceUser;
            users = allUsers.Where(p => p.Id == request.UserId || p.ReferanceUser == request.UserId || p.Id == parentUserId).ToList();
        }
        else if (!string.IsNullOrEmpty(request.UserEmail))
        {
            int userId = allUsers.Where(p => p.Email == request.UserEmail).FirstOrDefault().Id;
            parentUserId = allUsers.Where(p => p.Id == request.UserId).FirstOrDefault().ReferanceUser;

            users = allUsers.Where(p => p.Id == userId || p.ReferanceUser == userId || p.Id == parentUserId).ToList();

        }
        else if (request.UserId > 0 || !string.IsNullOrEmpty(request.UserEmail) || !string.IsNullOrEmpty(request.UserName))
        {
            int userId = allUsers.Where(p => p.Username == request.UserName).FirstOrDefault().Id;
            parentUserId = allUsers.Where(p => p.Id == request.UserId).FirstOrDefault().ReferanceUser;
            users = allUsers.Where(p => p.Id == userId || p.ReferanceUser == userId || p.Id == parentUserId).ToList();

        }
        else users = allUsers;



        return new GetOrganizationalChartQueryResponse(users);
    }
}
