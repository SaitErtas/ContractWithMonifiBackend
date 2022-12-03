using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;

namespace MonifiBackend.UserModule.Domain.Users;

public sealed class UserIP : BaseActivityDomain<int>
{
    private UserIP() { }
    public string IpAddress { get; private set; }
    public string RequestName { get; private set; }
    public static UserIP CreateNew(string ipAddress, string requestName)
    {
        AppRule.NotNullOrEmpty<DomainException>(ipAddress, "IpAddress not null or empty", $"IpAddress not null or empty. IpAddress: {ipAddress}");
        AppRule.NotNullOrEmpty<DomainException>(requestName, "RequestName not null or empty", $"RequestName not null or empty. RequestName: {requestName}");

        return new UserIP()
        {
            IpAddress = ipAddress,
            RequestName = requestName
        };
    }

    public static UserIP Default() => new();

    public static UserIP Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string ipAddress,
        string requestName)
    {
        return new UserIP()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            IpAddress = ipAddress,
            RequestName = requestName
        };
    }
}