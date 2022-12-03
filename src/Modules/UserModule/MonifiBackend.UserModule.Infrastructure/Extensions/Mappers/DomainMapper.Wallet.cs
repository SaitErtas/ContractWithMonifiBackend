using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Wallets;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Wallet to WalletEntity 
    public static WalletEntity Map(this Wallet domain)
    {
        var wallet = new WalletEntity()
        {
            Id = domain.Id,
            WalletAddress = domain.WalletAddress,
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            Status = domain.Status.ToInt(),
            CryptoNetworkId = domain.CryptoNetwork.Id
        };
        return wallet;
    }
    #endregion
    #region WalletEntity to Wallet 
    public static Wallet Map(this WalletEntity entity)
    {
        if (entity == null)
            return Wallet.Default();

        return Wallet.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.WalletAddress,
            entity.CryptoNetwork.Map(),
            entity.CreatedAt,
            entity.ModifiedAt);
    }
    #endregion
}