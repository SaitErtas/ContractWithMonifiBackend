using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.Settings;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.Settings;

public class SettingCommandDataAdapter : ISettingCommandDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public SettingCommandDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<bool> SaveAsync(Setting setting)
    {
        _dbContext.Settings.Update(setting.Map());
        return (await _dbContext.SaveChangesAsync()) > 0;
    }
}