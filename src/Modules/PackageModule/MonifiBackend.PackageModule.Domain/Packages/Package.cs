using MonifiBackend.Core.Domain.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.PackageDetailModule.Domain.PackageDetails;

namespace MonifiBackend.PackageModule.Domain.Packages;

public sealed class Package : BaseActivityDomain<int>, IAggregateRoot
{
    public string Name { get; private set; }
    public int MinValue { get; private set; }
    public int MaxValue { get; private set; }
    public int ChangePeriodDay { get; private set; }
    public int Bonus { get; private set; }
    public string Icon { get; private set; }
    private List<PackageDetail> _details = new();
    public IReadOnlyCollection<PackageDetail> Details => _details.AsReadOnly();

    public static Package Default() => new();

    public void SetName(string name)
    {
        Name = name;
    }
    public void SetMinValue(int minValue)
    {
        MinValue = minValue;
    }
    public void SetMaxValue(int maxValue)
    {
        MaxValue = maxValue;
    }
    public void SetBonus(int bonus)
    {
        Bonus = bonus;
    }
    public void SetChangePeriodDay(int changePeriodDay)
    {
        ChangePeriodDay = changePeriodDay;
    }
    public void SetIcon(string icon)
    {
        Icon = icon;
    }
    public void AddDetail(PackageDetail detail)
    {
        _details.Add(detail);
    }
    public static Package CreateNew(
        string name,
        int minValue,
        int maxValue,
        int changePeriodDay,
        string icon,
        int bonus,
        BaseStatus status)
    {
        AppRule.NotNullOrEmpty(name, new DomainException(DomainExceptionMessageType.NULL_OR_EMPTY, nameof(name), name));

        return new Package()
        {
            Name = name,
            ChangePeriodDay = changePeriodDay,
            Icon = icon,
            MaxValue = maxValue,
            MinValue = minValue,
            Status = status,
            Bonus = bonus,
        };
    }
    public static Package Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string name,
        int minValue,
        int maxValue,
        int changePeriodDay,
        string icon,
        int bonus,
        List<PackageDetail> details)
    {
        return new Package()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            Name = name,
            MinValue = minValue,
            MaxValue = maxValue,
            ChangePeriodDay = changePeriodDay,
            Icon = icon,
            Bonus = bonus,
            _details = details
        };
    }
}