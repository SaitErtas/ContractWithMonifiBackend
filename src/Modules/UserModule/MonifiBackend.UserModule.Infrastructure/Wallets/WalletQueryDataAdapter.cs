using Microsoft.EntityFrameworkCore;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.UserModule.Domain.Wallets;
using MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.UserModule.Infrastructure.Wallets;

public class WalletQueryDataAdapter : IWalletQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public WalletQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<List<Network>> GetNetworksAsync()
    {
        return await _dbContext.Networks
            .Select(x => x.Map())
            .AsNoTracking()
            .ToListAsync();
    }
    public async Task<Network> GetNetworkAsync(int id)
    {
        var network = await _dbContext.Networks
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id);
        return network.Map();
    }
}
