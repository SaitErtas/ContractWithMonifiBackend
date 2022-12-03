using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.UserModule.Domain.Localizations;

public class Country : BaseDomain<int>
{
    public string Name { get; private set; }
    public string Flag { get; private set; }
    public string Iso2 { get; private set; }
    public string Iso3 { get; private set; }
    public static Country Default() => new();

    public static Country CreateNew(int id)
    {
        return new Country()
        {
            Id = id,
        };
    }
    public static Country Map(
            int id,
            BaseStatus status,
            string name,
            string flag,
            string iso2,
            string iso3)
    {
        return new Country()
        {
            Id = id,
            Status = status,
            Name = name,
            Flag = flag,
            Iso2 = iso2,
            Iso3 = iso3,
        };
    }
}
