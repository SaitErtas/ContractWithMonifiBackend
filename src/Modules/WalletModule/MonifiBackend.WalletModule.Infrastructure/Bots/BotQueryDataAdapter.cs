using Microsoft.EntityFrameworkCore;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.Bots;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.Bots;

public class BotQueryDataAdapter : IBotQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public BotQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<List<Bot>> GetAsync()
    {
        return await _dbContext.Bots
            .Where(x => x.Status == BaseStatus.Active.ToInt())
            .AsNoTracking()
            .Select(x => x.Map())
            .ToListAsync();
    }
    public async Task<List<Bot>> GetActiveAsync()
    {
        return await _dbContext.Bots
            .Where(x => x.Status == BaseStatus.Active.ToInt())
            .AsNoTracking()
            .Select(x => x.Map())
            .ToListAsync();
    }

    public async Task<Bot> GetAsync(int id)
    {
        var bot = await _dbContext.Bots
            .FirstOrDefaultAsync(w => w.Id == id);
        return bot.Map();
    }
}