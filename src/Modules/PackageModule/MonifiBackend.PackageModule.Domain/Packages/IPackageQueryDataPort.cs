using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.PackageModule.Domain.ReadModel;

namespace MonifiBackend.PackageModule.Domain.Packages;

public interface IPackageQueryDataPort : IQueryDataPort
{
    Task<List<Package>> GetsAsync();
    Task<List<PackageDetailReadModel>> GetPackageDetailAsync();
    Task<bool> GetAsync(int duration);
    Task<Package> GetPackageAsync(int id);
}
