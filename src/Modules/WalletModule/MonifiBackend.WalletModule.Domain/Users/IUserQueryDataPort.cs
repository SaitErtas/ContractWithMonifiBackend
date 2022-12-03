namespace MonifiBackend.WalletModule.Domain.Users;

public interface IUserQueryDataPort
{
    Task<int> GetUserCountAsync();
    Task<int> GetReferanceCountAsync(int id);
    Task<User> GetUserAsync(int id);
    Task<bool> GetCheckUserIpAsync(int userId, string ipAddress);
    Task<User> GetUserEmailAsync(string email);
    Task<List<User>> GetMeFirstNetworkAsync(int id);
    Task<List<User>> GetAllNetworkAsync(List<int> ids);
    Task<User> GetRandomMonifiUser();

    Task<decimal> GetTotalSaleAsync(int id);
    Task<decimal> GetTotalBonusAsync(int id);
    Task<decimal> GetNotCommissionTotalSaleAsync(int id);
}
