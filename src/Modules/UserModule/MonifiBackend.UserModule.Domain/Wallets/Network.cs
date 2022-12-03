using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;

namespace MonifiBackend.UserModule.Domain.Wallets;

public sealed class Network : BaseActivityDomain<int>
{
    private Network() { }
    public string Name { get; private set; }
    public static Network CreateNew(string name)
    {
        AppRule.NotNullOrEmpty<DomainException>(name, "Name not null or empty", $"Name not null or empty. Name: {name}");

        return new Network()
        {
            Name = name
        };
    }

    public static Network Default() => new();

    public static Network Map(
        int id,
        BaseStatus status,
        string name,
        DateTime createdAt,
        DateTime modifiedAt)
    {
        return new Network()
        {
            Id = id,
            Status = status,
            Name = name,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt
        };
    }
}