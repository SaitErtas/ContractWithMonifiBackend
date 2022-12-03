using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.UserModule.Domain.Localizations;

public class Language : BaseDomain<int>
{
    public string Name { get; private set; }
    public string NativeName { get; private set; }
    public string ShortName { get; private set; }
    public static Language Default() => new();
    public static Language CreateNew(int id)
    {
        return new Language()
        {
            Id = id,
        };
    }
    public static Language Map(
            int id,
            BaseStatus status,
            string name,
            string nativeName,
            string shortName)
    {
        return new Language()
        {
            Id = id,
            Status = status,
            Name = name,
            NativeName = nativeName,
            ShortName = shortName,
        };
    }
}
