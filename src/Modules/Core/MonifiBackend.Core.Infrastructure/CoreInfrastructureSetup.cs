using AspNetCoreRateLimit;
using MediatR;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Localization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using MonifiBackend.Core.Domain.BscScans;
using MonifiBackend.Core.Domain.Caching;
using MonifiBackend.Core.Domain.Logging;
using MonifiBackend.Core.Domain.Notifications;
using MonifiBackend.Core.Domain.TronNetworks;
using MonifiBackend.Core.Infrastructure.BscScans;
using MonifiBackend.Core.Infrastructure.Caching;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.Core.Infrastructure.Logging;
using MonifiBackend.Core.Infrastructure.Middlewares;
using MonifiBackend.Core.Infrastructure.Notifications;
using MonifiBackend.Core.Infrastructure.TronNetworks;
using MonifiBackend.Data.Infrastructure.Contexts;
using System.Globalization;
using System.Text;

namespace MonifiBackend.Core.Infrastructure
{
    public static class CoreInfrastructureSetup
    {
        public static IServiceCollection ConfigureCoreInfrastructure(this IServiceCollection services, ApplicationSettings applicationSettings)
        {
            services.AddSingleton<ILogPort, LogAdapter>();
            services.AddSingleton<IEmailPort, GoogleEmailAdapter>();
            services.AddEfDatabaseClient(applicationSettings);
            services.AddHttpContextAccessor();
            services.AddRateLimiting();
            services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ValidationBehaviour<,>));
            services.AddTransient(typeof(IPipelineBehavior<,>), typeof(LoggingBehaviour<,>));
            services.AddHttpClient<IBscScanAccountsDataPort, BscScanAccountsDataAdapter>();
            services.AddHttpClient<ITronNetworkAccountsDataPort, TronNetworkAccountsDataAdapter>();
            services.AddLocalization();

            return services;
        }
        public static IServiceCollection AddEfDatabaseClient(this IServiceCollection services, ApplicationSettings applicationSettings)
        {
            services.AddDbContext<MonifiBackendDbContext>(options =>
            {
                options.UseSqlServer(applicationSettings.MssqlSettings.ConnectionStrings, m => m.MigrationsAssembly("MonifiBackend.API")
                    .UseQuerySplittingBehavior(QuerySplittingBehavior.SingleQuery));
            }, ServiceLifetime.Scoped);

            services.AddScoped<IMonifiBackendDbContext, MonifiBackendDbContext>();
            services.AddJwt(applicationSettings);
            return services;
        }
        public static IServiceCollection AddJwt(this IServiceCollection services, ApplicationSettings applicationSettings)
        {
            //Adding Athentication - JWT
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(o =>
                {
                    o.RequireHttpsMetadata = false;
                    o.SaveToken = false;
                    o.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,
                        ValidIssuer = applicationSettings.Secret.Issuer,
                        ValidAudience = applicationSettings.Secret.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(applicationSettings.Secret.Key))
                    };
                });
            return services;
        }
        public static IServiceCollection AddRedis(this IServiceCollection services)
        {
            services.AddSingleton<RedisServer>();
            services.AddSingleton<ICachePort, RedisCacheAdapter>();

            return services;
        }
        public static IServiceCollection AddLocalization(this IServiceCollection services)
        {
            services.AddLocalization(options =>
            {
                options.ResourcesPath = "Resources";
            });

            services.Configure<RequestLocalizationOptions>(options =>
            {
                var supportedCultures = new[]
                {
                    new CultureInfo("en-US"),
                    new CultureInfo("tr-TR"),
                };

                options.DefaultRequestCulture = new RequestCulture(culture: "en-US", uiCulture: "en-US");
                options.SupportedCultures = supportedCultures;
                options.SupportedUICultures = supportedCultures;
            });

            return services;
        }
        public static IServiceCollection AddRateLimiting(this IServiceCollection services)
        {
            services.AddMemoryCache();
            services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
            services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
            services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
            services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();
            services.AddInMemoryRateLimiting();

            services.Configure<IpRateLimitOptions>(options =>
            {
                options.EnableEndpointRateLimiting = true;
                options.StackBlockedRequests = false;
                options.RealIpHeader = "X-Real-IP";
                options.ClientIdHeader = "X-ClientId";
                options.QuotaExceededResponse = new QuotaExceededResponse
                {
                    Content = "{{ \"message\": \"The request limit has been exceeded.\", \"details\": \"Quota exceeded. You can make {0} requests per {1}. Please try again in {2} seconds.\" }}",
                    ContentType = "application/json",
                    StatusCode = 429
                };

                options.GeneralRules = new List<RateLimitRule>
                {
                    new RateLimitRule
                    {
                        Endpoint = "*",
                        Period = "1s",
                        Limit = 20,
                    }
                };
            });
            return services;
        }
    }
}
