using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.Bots;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.Bots;

internal class BotCommandDataAdapter : IBotCommandDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public BotCommandDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }
    public async Task<int> CreateAsync(Bot bot)
    {
        var botEntity = bot.Map();
        await _dbContext.Bots.AddAsync(botEntity);
        var result = await _dbContext.SaveChangesAsync();
        return result > 0 ? botEntity.Id : 0;
    }

    public async Task<bool> SaveAsync(Bot bot)
    {
        _dbContext.Bots.Update(bot.Map());
        return (await _dbContext.SaveChangesAsync()) > 0;
    }
}