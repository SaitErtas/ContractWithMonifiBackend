using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.WalletModule.Domain.Packages;

public sealed class Package : ReadOnlyBaseDomain<int>
{
    public string Name { get; private set; }
    public int MinValue { get; private set; }
    public int MaxValue { get; private set; }
    public int Bonus { get; private set; }
    public int ChangePeriodDay { get; private set; }
    private List<PackageDetail> _details = new();
    public IReadOnlyCollection<PackageDetail> Details => _details.AsReadOnly();
    public static Package Default() => new();

    public static Package Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string name,
        int minValue,
        int maxValue,
        int changePeriodDay,
        int bonus,
        List<PackageDetail> packageDetail)
    {
        return new Package()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            Name = name,
            ChangePeriodDay = changePeriodDay,
            Bonus = bonus,
            MaxValue = maxValue,
            MinValue = minValue,
            _details = packageDetail
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
        int bonus)
    {
        return new Package()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            Name = name,
            ChangePeriodDay = changePeriodDay,
            Bonus = bonus,
            MaxValue = maxValue,
            MinValue = minValue
        };
    }
}