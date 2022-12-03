using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Localizations;

namespace MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

public static partial class DomainMapper
{
    #region Country to CountryEntity 
    public static CountryEntity Map(this Country domain)
    {
        return new CountryEntity()
        {
            Id = domain.Id,
            Name = domain.Name,
            Flag = domain.Flag,
            Iso2 = domain.Iso2,
            Iso3 = domain.Iso3,
        };
    }
    #endregion
    #region CountryEntity to Country 
    public static Country Map(this CountryEntity entity)
    {
        if (entity == null)
            return Country.Default();

        return Country.Map(entity.Id,
            entity.Status.ToEnum<BaseStatus>(),
            entity.Name,
            entity.Flag,
            entity.Iso2,
            entity.Iso3);
    }
    #endregion
}
