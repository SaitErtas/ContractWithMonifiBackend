using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.PackageModule.Domain.Packages;
using MonifiBackend.PackageModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.PackageModule.Infrastructure.Packages;

public class PackageCommandDataAdapter : IPackageCommandDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public PackageCommandDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }
    public async Task<int> CreateAsync(Package package)
    {
        var packageEntity = package.Map();
        await _dbContext.Packages.AddAsync(packageEntity);
        var result = await _dbContext.SaveChangesAsync();
        return result > 0 ? packageEntity.Id : 0;
    }

    public async Task<bool> SaveAsync(Package package)
    {
        _dbContext.Packages.Update(package.Map());
        return (await _dbContext.SaveChangesAsync()) > 0;
    }
}
