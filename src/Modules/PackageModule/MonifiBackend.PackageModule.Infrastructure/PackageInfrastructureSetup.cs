using Microsoft.Extensions.DependencyInjection;
using MonifiBackend.PackageModule.Domain.Packages;
using MonifiBackend.PackageModule.Infrastructure.Packages;

namespace MonifiBackend.PackageModule.Infrastructure;

public static class PackageInfrastructureSetup
{
    public static IServiceCollection AddPackageServiceInfrastructure(this IServiceCollection services)
    {
        #region Ports-Adapters
        services.AddScoped<IPackageCommandDataPort, PackageCommandDataAdapter>();
        services.AddScoped<IPackageQueryDataPort, PackageQueryDataAdapter>();
        #endregion
        return services;
    }
}