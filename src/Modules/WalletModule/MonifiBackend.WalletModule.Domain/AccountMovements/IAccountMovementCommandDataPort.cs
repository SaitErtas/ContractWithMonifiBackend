using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Domain.AccountMovements;

public interface IAccountMovementCommandDataPort : ICommandDataPort
{
    Task<bool> SaveAsync(Wallet wallet);
    Task<bool> SaveAsync(AccountMovement accountMovement);
    Task BulkSaveAsync(List<AccountMovement> wallets);
}
