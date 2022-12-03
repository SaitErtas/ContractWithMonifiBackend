using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Localizations;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Language to LanguageEntity 
    public static LanguageEntity Map(this Language domain)
    {
        return new LanguageEntity()
        {
            Id = domain.Id,
            Name = domain.Name,
            NativeName = domain.NativeName,
            ShortName = domain.ShortName,
        };
    }
    #endregion
    #region LanguageEntity to Language 
    public static Language Map(this LanguageEntity entity)
    {
        if (entity == null)
            return Language.Default();

        return Language.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.Name,
            entity.NativeName,
            entity.ShortName);
    }
    #endregion
}