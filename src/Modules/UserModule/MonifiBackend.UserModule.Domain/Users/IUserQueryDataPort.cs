using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Resources;
using MonifiBackend.UserModule.Domain.Users.Notifications;

namespace MonifiBackend.UserModule.Domain.Users;

public interface IUserQueryDataPort : IQueryDataPort
{
    Task<QueryResult<User>> GetListAsync(QueryObject userQuery);
    Task<List<User>> GetAsync();
    Task<User> GetAsync(int id);
    Task<User> GetAsync(string email);
    Task<User> GetAsync(string email, string password);
    Task<User> GetUserConfirmationCodeAsync(string confirmationCode);
    Task<bool> CheckUserEmailAsync(string email);
    Task<bool> CheckIPAdressAsync(string ipAddress);
    Task<User> CheckWalletAddressAsync(string walletAddress);
    Task<User> GetReferanceCodeUserAsync(string referanceCode);
    Task<bool> CheckUserReferanceCodeAsync(string referanceCode);
    Task<bool> CheckUserResetPasswordCodeAsync(string resetPasswordCode);
    Task<bool> CheckUserConfirmationCodeAsync(string confirmationCode);
    Task<bool> CheckUseFa2CodeAsync(string fa2Code);
    Task<User> GetEmailAsync(string email);
    Task<User> GetResetPasswordCodeAsync(string resetPasswordCode);
    Task<List<User>> GetMeFirstNetworkAsync(int id);
    Task<List<User>> GetAllNetworkAsync(List<int> ids);

    Task<decimal> GetTotalSaleAsync(int id);
    Task<decimal> GetTotalBonusAsync(int id);

    Task<List<UserNotification>> GetNotificationsAsync(int userId);
}
