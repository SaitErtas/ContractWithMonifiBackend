using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetAccountMovements;
using System.Reflection;

namespace MonifiBackend.WalletModule.Application;

public static class WalletApplicationSetup
{
    public static IServiceCollection AddWalletServiceApplication(this IServiceCollection services)
    {
        services.AddMediatR(typeof(GetAccountMovementsQuery).GetTypeInfo().Assembly);
        services.AddValidatorsFromAssembly(typeof(GetAccountMovementsQueryValidator).Assembly);

        return services;
    }
}