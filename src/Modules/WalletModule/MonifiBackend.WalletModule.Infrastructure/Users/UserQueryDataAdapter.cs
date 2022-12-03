using Microsoft.EntityFrameworkCore;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.Users;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.Users;

public class UserQueryDataAdapter : IUserQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public UserQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<int> GetUserCountAsync()
    {
        return await _dbContext.Users.CountAsync();
    }

    public async Task<int> GetReferanceCountAsync(int id)
    {
        return await _dbContext.Users.CountAsync(x => x.ReferanceUser == id);
    }

    public async Task<User> GetUserAsync(int id)
    {
        var userEntity = await _dbContext.Users
            .Include(i => i.Wallet)
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id);
        return userEntity.Map();
    }
    public async Task<List<User>> GetMeFirstNetworkAsync(int id)
    {
        return await _dbContext.Users
            .Where(x => x.ReferanceUser == id)
            .Select(x => x.Map())
            .AsNoTracking()
            .ToListAsync();
    }

    public async Task<List<User>> GetAllNetworkAsync(List<int> ids)
    {
        return await _dbContext.Users
            .Where(x => ids.Any(p2 => x.Id == p2))
            .Select(x => x.Map())
            .AsNoTracking()
            .ToListAsync();
    }
    public async Task<decimal> GetTotalBonusAsync(int userId)
    {
        var totalSales = await _dbContext.AccountMovements
            .Include(i => i.PackageDetail)
            .Include(i => i.Wallet)
            .Where(w => w.Wallet.UserId == userId && w.TransactionStatus == TransactionStatus.Successful.ToInt() && w.ActionType == ActionType.Bonus.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Select(s => new { s.Amount, s.PackageDetail.Commission })
            .AsNoTracking()
            .ToListAsync();

        return totalSales.Sum(s => MathExtensions.PercentageCalculation(s.Amount, s.Commission));
    }

    public async Task<decimal> GetTotalSaleAsync(int userId)
    {
        var totalSales = await _dbContext.AccountMovements
            .Include(i => i.PackageDetail)
            .Include(i => i.Wallet)
            .Where(w => w.Wallet.UserId == userId && w.TransactionStatus == TransactionStatus.Successful.ToInt() && w.ActionType == ActionType.Sale.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Select(s => new { s.Amount, s.PackageDetail.Commission })
            .AsNoTracking()
            .ToListAsync();

        return totalSales.Sum(s => MathExtensions.PercentageCalculation(s.Amount, s.Commission));
    }

    public async Task<decimal> GetNotCommissionTotalSaleAsync(int userId)
    {
        var totalSales = await _dbContext.AccountMovements
            .Include(i => i.PackageDetail)
            .Include(i => i.Wallet)
            .Where(w => w.Wallet.UserId == userId && w.TransactionStatus == TransactionStatus.Successful.ToInt() && w.ActionType == ActionType.Sale.ToInt() && w.Status != BaseStatus.Deleted.ToInt())
            .Select(s => new { s.Amount, s.PackageDetail.Commission })
            .AsNoTracking()
            .ToListAsync();

        return totalSales.Sum(s => s.Amount);
    }

    public async Task<User> GetRandomMonifiUser()
    {
        var userEntity = await _dbContext.Users
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .Where(w => w.Email.Contains("@monifi.io") && w.Email != "arewen@monifi.io" && w.Email != "admin@monifi.io")
            .OrderBy(r => Guid.NewGuid())
            .AsNoTracking()
            .FirstOrDefaultAsync();
        return userEntity.Map();
    }

    public async Task<User> GetUserEmailAsync(string email)
    {
        var userEntity = await _dbContext.Users
            .Include(i => i.Wallet)
            .ThenInclude(i => i.CryptoNetwork)
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Email == email);
        return userEntity.Map();
    }

    public async Task<bool> GetCheckUserIpAsync(int userId, string ipAddress)
    {
        return await _dbContext.UserIPs
            .AnyAsync(a => a.IpAddress == ipAddress && a.UserId != userId);
    }
}