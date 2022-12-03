using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using MonifiBackend.PackageModule.Application.Packages.Commands.CreatePackage;
using System.Reflection;

namespace MonifiBackend.PackageModule.Application;

public static class PackageApplicationSetup
{
    public static IServiceCollection AddPackageServiceApplication(this IServiceCollection services)
    {
        services.AddMediatR(typeof(CreatePackageCommand).GetTypeInfo().Assembly);
        services.AddValidatorsFromAssembly(typeof(CreatePackageCommandValidator).Assembly);

        return services;
    }
}
