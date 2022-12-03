using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.UserModule.Domain.Wallets;

namespace MonifiBackend.UserModule.Infrastructure.Wallets;

public class WalletCommandDataAdapter : IWalletCommandDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public WalletCommandDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }
}
