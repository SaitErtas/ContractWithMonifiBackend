using Microsoft.EntityFrameworkCore;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Resources;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Extensions;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.UserModule.Domain.Users.Notifications;
using MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;
using System.Linq.Expressions;

namespace MonifiBackend.UserModule.Infrastructure.Users;

public class UserQueryDataAdapter : IUserQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public UserQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }
    public async Task<QueryResult<User>> GetListAsync(QueryObject userQuery)
    {
        var query = _dbContext.Users
            .Include(x => x.Phones.Where(q => q.Status == BaseStatus.Active.ToInt()))
             .Where(x => x.Status == BaseStatus.Active.ToInt())
            .AsQueryable();


        var columnsOrder = new Dictionary<string, Expression<Func<UserEntity, object>>>
        {
            ["id"] = x => x.Id
        };

        query = query.ApplyOrdering(userQuery, columnsOrder);
        query = query.ApplyPaging(userQuery);

        var queryResult = new QueryResult<User>(await query.CountAsync(), await query.Select(x => x.Map()).ToListAsync());
        return queryResult;
    }
    public async Task<User> GetAsync(int id)
    {
        var userEntity = await _dbContext.Users
            .Include(x => x.Language)
            .Include(x => x.Country)
            .Include(x => x.Wallet)
            .ThenInclude(x => x.CryptoNetwork)
            .Include(x => x.Phones.Where(q => q.Status == BaseStatus.Active.ToInt()))
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id);
        return userEntity.Map();
    }
    public async Task<User> GetAsync(string email, string password)
    {
        var userEntity = await _dbContext.Users
            .Include(x => x.Language)
            .Include(x => x.Country)
            .Include(x => x.Wallet)
            .ThenInclude(x => x.CryptoNetwork)
            .Include(x => x.Phones.Where(q => q.Status == BaseStatus.Active.ToInt()))
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Email == email && x.Password == password && x.Status == BaseStatus.Active.ToInt());
        return userEntity.Map();
    }
    public async Task<bool> CheckUserEmailAsync(string email)
    {
        return await _dbContext.Users
            .AnyAsync(x => x.Email == email);
    }
    public async Task<User> GetReferanceCodeUserAsync(string referanceCode)
    {
        var userEntity = await _dbContext.Users
            .Include(x => x.Language)
            .Include(x => x.Country)
            .Include(x => x.Wallet)
            .ThenInclude(x => x.CryptoNetwork)
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.ReferanceCode == referanceCode && x.Status == BaseStatus.Active.ToInt());
        return userEntity.Map();
    }
    public async Task<bool> CheckUserReferanceCodeAsync(string referanceCode)
    {
        return await _dbContext.Users
            .AnyAsync(x => x.ReferanceCode == referanceCode && x.Status == BaseStatus.Active.ToInt());
    }
    public async Task<bool> CheckUserResetPasswordCodeAsync(string resetPasswordCode)
    {
        return await _dbContext.Users
            .AnyAsync(x => x.ResetPasswordCode == resetPasswordCode && x.Status == BaseStatus.Active.ToInt());
    }
    public async Task<bool> CheckUserConfirmationCodeAsync(string confirmationCode)
    {
        return await _dbContext.Users
            .AnyAsync(x => x.ConfirmationCode == confirmationCode);
    }
    public async Task<User> GetEmailAsync(string email)
    {
        var userEntity = await _dbContext.Users
            .Include(x => x.Language)
            .Include(x => x.Country)
            .Include(x => x.Wallet)
            .ThenInclude(x => x.CryptoNetwork)
            .Include(x => x.Phones.Where(q => q.Status == BaseStatus.Active.ToInt()))
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Email == email);
        return userEntity.Map();
    }
    public async Task<User> GetResetPasswordCodeAsync(string resetPasswordCode)
    {
        var userEntity = await _dbContext.Users
            .Include(x => x.Language)
            .Include(x => x.Country)
            .Include(x => x.Wallet)
            .ThenInclude(x => x.CryptoNetwork)
            .Include(x => x.Phones.Where(q => q.Status == BaseStatus.Active.ToInt()))
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.ResetPasswordCode == resetPasswordCode && x.Status == BaseStatus.Active.ToInt());
        return userEntity.Map();
    }

    public async Task<User> GetUserConfirmationCodeAsync(string confirmationCode)
    {
        var userEntity = await _dbContext.Users
            .Include(x => x.Language)
            .Include(x => x.Country)
            .Include(x => x.Wallet)
            .ThenInclude(x => x.CryptoNetwork)
            .Include(x => x.Phones.Where(q => q.Status == BaseStatus.Active.ToInt()))
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.ConfirmationCode == confirmationCode);
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
            .Where(x => ids.Any(p2 => x.ReferanceUser == p2))
            .Select(x => x.Map())
            .AsNoTracking()
            .ToListAsync();
    }

    public async Task<List<UserNotification>> GetNotificationsAsync(int userId)
    {
        return await _dbContext.Notifications
            .Include(i => i.User)
            .Where(x => x.User.Id == userId)
            .OrderByDescending(x => x.CreatedAt)
            .Take(15)
            .Select(x => x.Map())
            .AsNoTracking()
            .ToListAsync();
    }

    public async Task<User> CheckWalletAddressAsync(string walletAddress)
    {
        var userEntity = await _dbContext.Users
            .Include(i => i.Wallet)
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Wallet.WalletAddress == walletAddress);
        return userEntity.Map();
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
            .ToListAsync();

        return totalSales.Sum(s => MathExtensions.PercentageCalculation(s.Amount, s.Commission));
    }

    public async Task<List<User>> GetAsync()
    {
        return await _dbContext.Users
            .Include(x => x.Language)
            .Include(x => x.Country)
            .Include(x => x.Wallet)
            .ThenInclude(x => x.CryptoNetwork)
            .Include(x => x.Phones.Where(q => q.Status == BaseStatus.Active.ToInt()))
            .Where(w => !w.Email.Contains("@monifi.io"))
            .Select(x => x.Map())
            .AsNoTracking()
            .ToListAsync();

    }

    public async Task<bool> CheckIPAdressAsync(string ipAddress)
    {
        return await _dbContext.UserIPs
            .AnyAsync(a => a.IpAddress == ipAddress);
    }

    public async Task<bool> CheckUseFa2CodeAsync(string fa2Code)
    {
        return await _dbContext.Users
            .AnyAsync(x => x.Fa2Code == fa2Code && x.Status == BaseStatus.Active.ToInt());
    }

    public async Task<User> GetAsync(string email)
    {
        var userEntity = await _dbContext.Users
            .Include(x => x.Language)
            .Include(x => x.Country)
            .Include(x => x.Wallet)
            .ThenInclude(x => x.CryptoNetwork)
            .Include(x => x.Phones.Where(q => q.Status == BaseStatus.Active.ToInt()))
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Email == email);
        return userEntity.Map();
    }
}
