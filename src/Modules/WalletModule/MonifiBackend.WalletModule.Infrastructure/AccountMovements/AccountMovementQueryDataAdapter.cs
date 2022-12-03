using Microsoft.EntityFrameworkCore;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.AccountMovements;

public class AccountMovementQueryDataAdapter : IAccountMovementQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public AccountMovementQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<List<AccountMovement>> GetAccountMovementsAsync(int userId)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.Wallet.UserId == userId && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .ToListAsync();
        return entity.Select(s => s.Map()).ToList();
    }

    public async Task<List<AccountMovement>> GetPurchasedMovementAsync(int userId)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.Wallet.UserId == userId && w.ActionType == ActionType.Sale.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .ToListAsync();

        return entity.Select(s => s.Map()).ToList();
    }

    public async Task<Wallet> GetUserWalletAsync(int userId)
    {
        var entity = await _dbContext.Wallets
            .Include(i => i.CryptoNetwork)
            .Include(i => i.AccountMovements.Where(q => q.Status == BaseStatus.Active.ToInt()))
            .AsNoTracking()
            .FirstOrDefaultAsync(w => w.UserId == userId);

        return entity.Map();
    }

    public async Task<decimal> GetTotalBonusAsync()
    {
        var totalSale = await _dbContext.AccountMovements
            .Where(w => w.ActionType == ActionType.Bonus.ToInt() && w.TransactionStatus == TransactionStatus.Successful.ToInt() && w.Status == BaseStatus.Active.ToInt())
            .SumAsync(s => s.Amount);
        return totalSale;
    }

    public async Task<decimal> GetTotalSaleAsync()
    {
        var totalSale = await _dbContext.AccountMovements
            .Where(w => w.ActionType == ActionType.Sale.ToInt() && w.TransactionStatus == TransactionStatus.Successful.ToInt() && w.Status == BaseStatus.Active.ToInt())
            .SumAsync(s => s.Amount);
        return totalSale;
    }

    public async Task<List<AccountMovement>> GetAllMovementAsync(TransactionStatus transactionStatus)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.TransactionStatus == transactionStatus.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .ToListAsync();
        return entity.Select(s => s.Map()).ToList();
    }
    public async Task<List<AccountMovement>> GetAllRealMovementAsync(TransactionStatus transactionStatus, ActionType actionType)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.TransactionStatus == transactionStatus.ToInt() && w.ActionType == actionType.ToInt() && w.Hash != "Monifi" && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.User)
            .OrderByDescending(o => o.TransferTime)
            .AsNoTracking()
            .ToListAsync();
        return entity.Select(s => s.Map()).ToList();
    }
    public async Task<List<AccountMovement>> GetAllRealMovementAsync(ActionType actionType)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.TransactionStatus != TransactionStatus.Fail.ToInt() && w.ActionType == actionType.ToInt() && w.Hash != "Monifi" && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.User)
            .OrderByDescending(o => o.TransferTime)
            .AsNoTracking()
            .ToListAsync();
        return entity.Select(s => s.Map()).ToList();
    }

    public async Task<List<AccountMovement>> GetUserMovementAsync(int userId)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.Wallet.UserId == userId && w.TransactionStatus == TransactionStatus.Successful.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .ToListAsync();
        return entity.Select(s => s.Map()).ToList();
    }

    public async Task<List<AccountMovement>> GetAllMovementAsync(int userId, TransactionStatus transactionStatus)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.Wallet.UserId == userId && w.TransactionStatus == transactionStatus.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .ToListAsync();
        return entity.Select(s => s.Map()).ToList();
    }

    public async Task<List<AccountMovement>> GetSaleMovementAsync(int userId, TransactionStatus transactionStatus)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.Wallet.UserId == userId && w.ActionType == ActionType.Sale.ToInt() && w.TransactionStatus == transactionStatus.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .ToListAsync();
        return entity.Select(s => s.Map()).ToList();
    }

    public async Task<AccountMovement> GetAccountMovementAsync(int accountMovementId)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.Id == accountMovementId && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .FirstOrDefaultAsync();
        return entity.Map();
    }

    public async Task<List<DaySaleStatistics>> GetDayOfSalesAsync()
    {
        DateTime startDate = DateTime.Now.AddDays(-9);
        DateTime endDate = DateTime.Now.AddDays(1);

        //get database sales from 29 days ago at midnight to the end of today
        var salesForPeriod = _dbContext.AccountMovements.Where(b => b.CreatedAt > startDate.Date && b.CreatedAt <= endDate.Date && b.TransactionStatus == TransactionStatus.Successful.ToInt() && b.ActionType == ActionType.Sale.ToInt() && b.Status == BaseStatus.Active.ToInt());

        var allDays = MoreEnumerable.GenerateByIndex(i => startDate.AddDays(i).Date).Take(10);

        var salesByDay = from s in salesForPeriod
                         group s by s.CreatedAt.Date into g
                         select new DaySaleStatistics { Day = g.Key, TotalSales = g.Sum(x => (decimal)x.Amount) };


        var query = from d in allDays
                    join s in salesByDay on d equals s.Day into j
                    from s in j.DefaultIfEmpty()
                    select new DaySaleStatistics { Day = d, TotalSales = (s != null) ? s.TotalSales : 0m };

        return query.ToList();
    }

    public async Task<List<AccountMovement>> GetNoBonusPurchasedMovementAsync(int userId)
    {
        var entity = await _dbContext.AccountMovements
            .Where(w => w.Wallet.UserId == userId && w.ActionType == ActionType.Sale.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Include(i => i.PackageDetail)
            .ThenInclude(i => i.Package)
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .ToListAsync();

        return entity.Select(s => s.Map()).ToList();
    }
}

public static partial class MoreEnumerable
{
    public static IEnumerable<TResult> GenerateByIndex<TResult>(Func<int, TResult> generator)
    {
        // Looping over 0...int.MaxValue inclusive is a pain. Simplest is to go exclusive,
        // then go again for int.MaxValue.
        for (int i = 0; i < int.MaxValue; i++)
        {
            yield return generator(i);
        }
        yield return generator(int.MaxValue);
    }

}