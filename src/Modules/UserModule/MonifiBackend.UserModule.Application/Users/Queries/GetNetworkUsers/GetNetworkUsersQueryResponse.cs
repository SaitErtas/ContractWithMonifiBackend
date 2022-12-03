using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetNetworkUsers;

public class GetNetworkUsersQueryResponse
{
    public GetNetworkUsersQueryResponse(User lead, List<User> meFirstNetworkUsers, List<User> networkUsers, IStringLocalizer<Resource> stringLocalizer)
    {
        var clearMeFirstNetworkUsers = meFirstNetworkUsers.Select(x => new GetUser(x.Email.CapitalizeFirstAndHideText(4), x.ReferanceCode.CapitalizeFirstAndHideText(), x.FullName.CapitalizeFirstAndHideText(4), $"{stringLocalizer["Member"]}", x.Id)).ToList();
        var clearNetworkUsers = networkUsers.Select(x => new GetUser(x.Email.CapitalizeFirstAndHideText(4), x.ReferanceCode.CapitalizeFirstAndHideText(), x.FullName.CapitalizeFirstAndHideText(4), $"{stringLocalizer["Sub"]}", x.Id)).ToList();
        var clearUser = new GetUser(lead.Email.CapitalizeFirstAndHideText(4), lead.ReferanceCode.CapitalizeFirstAndHideText(), lead.FullName.CapitalizeFirstAndHideText(4), $"{stringLocalizer["Leader"]}", lead.Id);
        NetworkUsers.Add(clearUser);
        NetworkUsers.AddRange(clearMeFirstNetworkUsers);
        NetworkUsers.AddRange(clearNetworkUsers);
        Count = NetworkUsers.Count();
    }
    public List<GetUser> NetworkUsers { get; private set; } = new();
    public int Count { get; private set; } = new();
}
public class GetUser
{
    public GetUser(string email, string referenceCode, string fullName, string status, int userId)
    {
        Email = email;
        ReferenceCode = referenceCode;
        FullName = fullName;
        Status = status;
        UserId = userId;
        Id = userId;
        UniqueKey = userId + " - " + status;
    }

    public string Email { get; set; }
    public string ReferenceCode { get; set; }
    public string FullName { get; set; }
    public string Status { get; set; }
    public int UserId { get; set; }
    public int Id { get; set; }
    public string UniqueKey { get; set; }
}