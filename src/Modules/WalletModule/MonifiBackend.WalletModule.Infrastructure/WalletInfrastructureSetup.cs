using Microsoft.Extensions.DependencyInjection;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Bots;
using MonifiBackend.WalletModule.Domain.Notifications;
using MonifiBackend.WalletModule.Domain.Packages;
using MonifiBackend.WalletModule.Domain.Settings;
using MonifiBackend.WalletModule.Domain.Users;
using MonifiBackend.WalletModule.Infrastructure.AccountMovements;
using MonifiBackend.WalletModule.Infrastructure.Bots;
using MonifiBackend.WalletModule.Infrastructure.Notifications;
using MonifiBackend.WalletModule.Infrastructure.Packages;
using MonifiBackend.WalletModule.Infrastructure.Settings;
using MonifiBackend.WalletModule.Infrastructure.Users;

namespace MonifiBackend.WalletModule.Infrastructure;

public static class WalletInfrastructureSetup
{
    public static IServiceCollection AddWalletServiceInfrastructure(this IServiceCollection services)
    {
        #region Ports-Adapters
        services.AddScoped<IAccountMovementCommandDataPort, AccountMovementCommandDataAdapter>();
        services.AddScoped<IAccountMovementQueryDataPort, AccountMovementQueryDataAdapter>();
        services.AddScoped<IPackageQueryDataPort, PackageQueryDataAdapter>();
        services.AddScoped<ISettingQueryDataPort, SettingQueryDataAdapter>();
        services.AddScoped<ISettingCommandDataPort, SettingCommandDataAdapter>();
        services.AddScoped<IUserQueryDataPort, UserQueryDataAdapter>();
        services.AddScoped<INotificationCommandDataPort, NotificationCommandDataAdapter>();

        services.AddScoped<IBotCommandDataPort, BotCommandDataAdapter>();
        services.AddScoped<IBotQueryDataPort, BotQueryDataAdapter>();
        #endregion
        return services;
    }
}