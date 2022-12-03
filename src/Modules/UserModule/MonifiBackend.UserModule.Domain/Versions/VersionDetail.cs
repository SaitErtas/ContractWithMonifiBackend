using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.UserModule.Domain.Versions;

public sealed class VersionDetail : BaseActivityDomain<int>
{
    public string Name { get; private set; }

    public Version Version { get; private set; }
    public static VersionDetail Default() => new();

    public static VersionDetail Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string name)
    {
        return new VersionDetail()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            Name = name,
        };
    }
}