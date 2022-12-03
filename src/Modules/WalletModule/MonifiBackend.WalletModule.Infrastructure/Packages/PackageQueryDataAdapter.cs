using Microsoft.EntityFrameworkCore;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.WalletModule.Domain.Packages;
using MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.WalletModule.Infrastructure.Packages;

public class PackageQueryDataAdapter : IPackageQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public PackageQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }
    public async Task<bool> GetAsync(int duration)
    {
        return await _dbContext.Packages
            .AnyAsync(x => x.PackageDetails.Any(x => x.Duration == duration) && x.Status != BaseStatus.Deleted.ToInt());
    }

    public async Task<PackageDetail> GetPackageDetailAsync(int id)
    {
        var packageEntity = await _dbContext.PackageDetails
            .Include(i => i.Package)
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id && x.Status != BaseStatus.Deleted.ToInt());
        return packageEntity.Map();
    }

    public async Task<Package> GetPackageDetailIdAsync(int detailId)
    {
        var packageEntity = await _dbContext.Packages
            .Include(i => i.PackageDetails)
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.PackageDetails.Any(a => a.Id == detailId) && x.Status != BaseStatus.Deleted.ToInt());
        return packageEntity.Map();
    }

    public async Task<List<Package>> GetsAsync()
    {
        var packagesEntity = await _dbContext.Packages
            .Include(i => i.PackageDetails)
            .Where(x => x.Status != BaseStatus.Deleted.ToInt())
            .AsNoTracking()
            .ToListAsync();

        return packagesEntity.Select(x => x.Map()).ToList();
    }
}
