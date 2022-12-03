using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.PackageModule.Domain.Packages;

public interface IPackageCommandDataPort : ICommandDataPort
{
    Task<int> CreateAsync(Package package);
    Task<bool> SaveAsync(Package package);
}
