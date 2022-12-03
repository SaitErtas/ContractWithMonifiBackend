using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.WalletModule.Domain.AccountMovements;

namespace MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region AccountMovement to AccountMovementEntity 
    public static AccountMovementEntity Map(this AccountMovement domain)
    {
        return new AccountMovementEntity()
        {
            Id = domain.Id,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            ActionType = domain.ActionType.ToInt(),
            PackageDetailId = domain.PackageDetail.Id,
            WalletId = domain.Wallet.Id,
            TransactionStatus = domain.TransactionStatus.ToInt(),
            Amount = domain.Amount,
            Hash = domain.Hash,
            TokenSymbol = domain.TokenSymbol,
            TransferTime = domain.TransferTime,
        };
    }
    #endregion
    #region AccountMovementEntity to AccountMovement 
    public static AccountMovement Map(this AccountMovementEntity entity)
    {
        if (entity == null)
            return AccountMovement.Default();

        return AccountMovement.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Amount,
            entity.TransactionStatus.ToEnum<TransactionStatus>(),
            entity.ActionType.ToEnum<ActionType>(),
            entity.Hash,
            entity.TokenSymbol,
            entity.TransferTime,
            entity.PackageDetail.PackageMap(),
            entity.Wallet.Map());
    }
    #endregion
}
