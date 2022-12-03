using Microsoft.EntityFrameworkCore;
using MonifiBackend.Data.Infrastructure.Entities;

namespace MonifiBackend.Data.Infrastructure.Contexts
{
    public interface IMonifiBackendDbContext : IDbContext
    {
        DbSet<UserEntity> Users { get; set; }
        DbSet<UserPhoneEntity> UserPhones { get; set; }
        DbSet<PackageEntity> Packages { get; set; }
        DbSet<PackageDetailEntity> PackageDetails { get; set; }
        DbSet<CountryEntity> Countries { get; set; }
        DbSet<LanguageEntity> Languages { get; set; }
        DbSet<NetworkEntity> Networks { get; set; }
        DbSet<UserIPEntity> UserIPs { get; set; }
        DbSet<NotificationEntity> Notifications { get; set; }
        DbSet<WalletEntity> Wallets { get; set; }
        DbSet<AccountMovementEntity> AccountMovements { get; set; }
        DbSet<SettingEntity> Settings { get; set; }
        DbSet<VersionEntity> Versions { get; set; }
        DbSet<VersionDetailEntity> VersionDetails { get; set; }
        DbSet<BotEntity> Bots { get; set; }
    }
}
