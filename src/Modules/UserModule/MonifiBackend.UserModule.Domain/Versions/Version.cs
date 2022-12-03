using MonifiBackend.Core.Domain.Abstractions;
using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.UserModule.Domain.Versions;

public sealed class Version : BaseActivityDomain<int>, IAggregateRoot
{
    public string Name { get; private set; }
    private List<VersionDetail> _details = new();
    public IReadOnlyCollection<VersionDetail> Details => _details.AsReadOnly();

    public static Version Default() => new();

    public static Version Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string name,
        List<VersionDetail> details)
    {
        return new Version()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            Name = name,
            _details = details
        };
    }
}