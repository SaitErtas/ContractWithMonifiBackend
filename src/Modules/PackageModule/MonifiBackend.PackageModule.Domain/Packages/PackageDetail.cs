using MonifiBackend.Core.Domain.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.PackageModule.Domain.Packages;

namespace MonifiBackend.PackageDetailModule.Domain.PackageDetails;

public sealed class PackageDetail : BaseActivityDomain<int>, IAggregateRoot
{
    public string Name { get; private set; }
    public int Duration { get; private set; }
    public int Commission { get; private set; }

    public Package Package { get; private set; }
    public static PackageDetail Default() => new();

    public void SetName(string name)
    {
        Name = name;
    }
    public void SetDuration(int duration)
    {
        Duration = duration;
    }
    public void SetCommission(int commission)
    {
        Commission = commission;
    }
    public static PackageDetail CreateNew(
        string name,
        int duration,
        int commission,
        BaseStatus status)
    {
        AppRule.NotNullOrEmpty(name, new DomainException(DomainExceptionMessageType.NULL_OR_EMPTY, nameof(name), name));
        AppRule.NotNegativeOrZero(duration, new DomainException(DomainExceptionMessageType.NEGATIVE_OR_ZERO, nameof(duration), duration));
        AppRule.NotNegativeOrZero(commission, new DomainException(DomainExceptionMessageType.NEGATIVE_OR_ZERO, nameof(commission), commission));

        return new PackageDetail()
        {
            Name = name,
            Status = status,
            Duration = duration,
            Commission = commission,
        };
    }
    public static PackageDetail Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string name,
        int duration,
        int commission)
    {
        return new PackageDetail()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            Name = name,
            Duration = duration,
            Commission = commission
        };
    }
}