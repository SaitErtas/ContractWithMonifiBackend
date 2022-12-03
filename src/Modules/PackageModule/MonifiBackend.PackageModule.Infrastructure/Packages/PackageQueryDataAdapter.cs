using Microsoft.EntityFrameworkCore;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.PackageModule.Domain.Packages;
using MonifiBackend.PackageModule.Domain.ReadModel;
using MonifiBackend.PackageModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.PackageModule.Infrastructure.Packages;

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

    public async Task<Package> GetPackageAsync(int id)
    {
        var packageEntity = await _dbContext.Packages
            .Include(x => x.PackageDetails)
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id && x.Status == BaseStatus.Active.ToInt());
        return packageEntity.Map();
    }

    public async Task<List<PackageDetailReadModel>> GetPackageDetailAsync()
    {
        var packagesEntity = await _dbContext.PackageDetails
            .Include(i => i.Package)
            .Where(x => x.Status == BaseStatus.Active.ToInt())
            .AsNoTracking()
            .ToListAsync();

        return packagesEntity.Select(x => new PackageDetailReadModel(x.Id, $"{x.Package.Name} - {x.Duration}")).ToList();
    }

    public async Task<List<Package>> GetsAsync()
    {
        var packagesEntity = await _dbContext.Packages
            .Include(i => i.PackageDetails)
            .Where(x => x.Status == BaseStatus.Active.ToInt())
            .AsNoTracking()
            .ToListAsync();

        return packagesEntity.Select(x => x.Map()).ToList();
    }
}
