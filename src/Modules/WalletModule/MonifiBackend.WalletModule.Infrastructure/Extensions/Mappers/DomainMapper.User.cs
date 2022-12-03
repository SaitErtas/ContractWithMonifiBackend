using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region User to UserEntity 
    public static UserEntity Map(this User domain)
    {
        return new UserEntity()
        {
            Id = domain.Id,
            Email = domain.Email,
            Password = domain.Password,
            Terms = domain.Terms,
            Status = domain.Status.ToInt(),
            CreatedAt = domain.CreatedAt,
            ModifiedAt = domain.ModifiedAt,
            ResetPasswordCode = domain.ResetPasswordCode,
            ReferanceUser = domain.ReferanceUser,
            ConfirmationCode = domain.ConfirmationCode,
            ReferanceCode = domain.ReferanceCode,
            FullName = domain.FullName,
            Username = domain.Username,
            Fa2Code = domain.Fa2Code,
            Wallet = domain.Wallet.Map()
        };
    }
    #endregion
    #region UserEntity to User 
    public static User Map(this UserEntity entity)
    {
        if (entity == null)
            return User.Default();

        return User.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.Email,
            entity.Password,
            entity.Username,
            entity.Terms,
            entity.ResetPasswordCode,
            entity.ReferanceUser,
            entity.ReferanceCode,
            entity.ConfirmationCode,
            entity.FullName,
            entity.Fa2Code,
            entity.Wallet.Map(),
            entity.CreatedAt,
            entity.ModifiedAt);
    }
    #endregion
    #region UserEntity to User 
    public static User SingleMap(this UserEntity entity)
    {
        if (entity == null)
            return User.Default();

        return User.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.Email,
            entity.Password,
            entity.Username,
            entity.Terms,
            entity.ResetPasswordCode,
            entity.ReferanceUser,
            entity.ReferanceCode,
            entity.ConfirmationCode,
            entity.FullName,
            entity.Fa2Code,
            entity.CreatedAt,
            entity.ModifiedAt);
    }
    #endregion
}
