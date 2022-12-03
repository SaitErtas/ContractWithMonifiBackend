using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.WalletModule.Domain.AccountMovements;

public interface IAccountMovementQueryDataPort : IQueryDataPort
{
    Task<List<AccountMovement>> GetAllMovementAsync(TransactionStatus transactionStatus);
    Task<List<AccountMovement>> GetAllRealMovementAsync(TransactionStatus transactionStatus, ActionType actionType);
    Task<List<AccountMovement>> GetAllRealMovementAsync(ActionType actionType);
    Task<List<AccountMovement>> GetAllMovementAsync(int userId, TransactionStatus transactionStatus);
    Task<List<AccountMovement>> GetSaleMovementAsync(int userId, TransactionStatus transactionStatus);
    Task<List<AccountMovement>> GetUserMovementAsync(int userId);
    Task<List<AccountMovement>> GetPurchasedMovementAsync(int userId);
    Task<List<AccountMovement>> GetNoBonusPurchasedMovementAsync(int userId);
    Task<List<AccountMovement>> GetAccountMovementsAsync(int userId);
    Task<AccountMovement> GetAccountMovementAsync(int accountMovementId);
    Task<Wallet> GetUserWalletAsync(int userId);
    Task<decimal> GetTotalSaleAsync();
    Task<decimal> GetTotalBonusAsync();
    Task<List<DaySaleStatistics>> GetDayOfSalesAsync();
}
