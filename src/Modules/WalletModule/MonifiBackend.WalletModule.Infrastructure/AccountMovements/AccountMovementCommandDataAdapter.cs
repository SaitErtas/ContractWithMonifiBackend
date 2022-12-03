using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.AccountMovements;

public class AccountMovementCommandDataAdapter : IAccountMovementCommandDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public AccountMovementCommandDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<bool> SaveAsync(Wallet wallet)
    {
        _dbContext.Wallets.Update(wallet.Map());
        return (await _dbContext.SaveChangesAsync()) > 0;
    }

    public async Task BulkSaveAsync(List<AccountMovement> accountMovements)
    {
        _dbContext.AccountMovements.UpdateRange(accountMovements.Select(x => x.Map()).ToList());
        await _dbContext.SaveChangesAsync();
    }

    public async Task<bool> SaveAsync(AccountMovement accountMovement)
    {
        _dbContext.AccountMovements.Update(accountMovement.Map());
        return (await _dbContext.SaveChangesAsync()) > 0;
    }
}
