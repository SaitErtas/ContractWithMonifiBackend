using Microsoft.Extensions.DependencyInjection;
using MonifiBackend.UserModule.Domain.Localizations;
using MonifiBackend.UserModule.Domain.Notifications;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.UserModule.Domain.Versions;
using MonifiBackend.UserModule.Domain.Wallets;
using MonifiBackend.UserModule.Infrastructure.Localizations;
using MonifiBackend.UserModule.Infrastructure.Notifications;
using MonifiBackend.UserModule.Infrastructure.Users;
using MonifiBackend.UserModule.Infrastructure.Versions;
using MonifiBackend.UserModule.Infrastructure.Wallets;

namespace MonifiBackend.UserModule.Infrastructure
{
    public static class UserInfrastructureSetup
    {
        public static IServiceCollection AddUserServiceInfrastructure(this IServiceCollection services)
        {
            #region Ports-Adapters
            services.AddScoped<IUserCommandDataPort, UserCommandDataAdapter>();
            services.AddScoped<IUserQueryDataPort, UserQueryDataAdapter>();
            services.AddScoped<ILocalizationQueryDataPort, LocalizationQueryDataAdapter>();
            services.AddScoped<IWalletQueryDataPort, WalletQueryDataAdapter>();
            services.AddScoped<INotificationCommandDataPort, NotificationCommandDataAdapter>();
            services.AddScoped<IJwtUtils, JwtUtils>();
            services.AddScoped<IVersionQueryDataPort, VersionQueryDataAdapter>();
            #endregion
            return services;
        }
    }
}
