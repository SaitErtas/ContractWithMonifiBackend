using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.WalletModule.Domain.Bots;

namespace MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;


public static partial class DomainMapper
{
    #region Bot to BotEntity 
    public static BotEntity Map(this Bot domain)
    {
        if (domain == null)
            domain = Bot.Default();

        return new BotEntity()
        {
            Id = domain.Id,
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            Status = domain.Status.ToInt(),
            Hour = domain.Hour,
            Minute = domain.Minute,
            WorkingRange = domain.WorkingRange.ToInt(),
            Range = domain.Range,
            Amount = domain.Amount,
            PackageDetailId = domain.PackageDetailId,
        };
    }
    #endregion
    #region BotEntity to Bot 
    public static Bot Map(this BotEntity entity)
    {
        if (entity == null)
            return Bot.Default();

        return Bot.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.CreatedAt,
            entity.ModifiedAt,
            entity.Hour,
            entity.Minute,
            entity.WorkingRange.ToEnum<WorkingRange>(),
            entity.Range,
            entity.Amount,
            entity.PackageDetailId);
    }
    #endregion
}