using Microsoft.EntityFrameworkCore;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.Settings;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.Settings;

public class SettingQueryDataAdapter : ISettingQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public SettingQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<Setting> GetAsync(int id)
    {
        var item = await _dbContext.Settings
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id);
        return item.Map();
    }
}