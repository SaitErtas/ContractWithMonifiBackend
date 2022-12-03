using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetUsers;

public class GetUsersQueryResponse
{
    public GetUsersQueryResponse(List<User> users)
    {
        Users = users.Select(x => new GetUserResponse(x)).ToList();
    }
    public List<GetUserResponse> Users { get; set; }
}
public class GetUserResponse
{
    public GetUserResponse(User user)
    {
        Id = user.Id;
        Role = user.Role.ToRole();
        UserName = user.Username;
        FullName = user.FullName;
        Email = user.Email;
        Country = user.Country.Name;
        WalletAddress = user.Wallet.WalletAddress;
        WalletAddressId = user.Wallet.Id;
        Language = user.Language.Name;
        ReferenceCode = user.ReferanceCode;
        Phone = user.Phones?.FirstOrDefault()?.Number;
        Avatar = user.Avatar;
        CryptoNetworkId = user.Wallet.CryptoNetwork.Id;
        CryptoNetwork = user.Wallet.CryptoNetwork.Name;
        CountryId = user.Country.Id;
        LanguageId = user.Language.Id;
        LanguageCode = user.Language.ShortName;
        Status = user.Status.ToString().ToLower();
        LanguageShortCode = LanguageCode.Substring(0, 2);
    }
    public int Id { get; set; }
    public string UserName { get; set; }
    public string FullName { get; set; }
    public string Email { get; set; }
    public int? WalletAddressId { get; set; }
    public string WalletAddress { get; set; }
    public string ReferenceCode { get; set; }
    public string Role { get; set; }
    public string Avatar { get; set; }
    public int? CryptoNetworkId { get; set; }
    public string CryptoNetwork { get; set; }
    public string Phone { get; set; }
    public string Country { get; set; }
    public int? CountryId { get; set; }
    public string Language { get; set; }
    public int? LanguageId { get; set; }
    public string? LanguageCode { get; set; }
    public string Status { get; set; }
    public string LanguageShortCode { get; set; }
    public string ActionCommand { get; set; } = "select";
}
