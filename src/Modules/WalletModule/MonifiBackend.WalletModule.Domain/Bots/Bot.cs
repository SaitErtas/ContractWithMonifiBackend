using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.WalletModule.Domain.Bots;

public sealed class Bot : BaseActivityDomain<int>
{
    public int Hour { get; private set; }
    public int Minute { get; private set; }
    public WorkingRange WorkingRange { get; private set; }
    public int Range { get; private set; }
    public int Amount { get; private set; }
    public int PackageDetailId { get; private set; }

    public static Bot Default() => new();

    public static Bot CreateNew(
        int hour,
        int minute,
        WorkingRange workingRange,
        int range,
        int amount,
        int packageDetailId,
        BaseStatus status)
    {
        return new Bot()
        {
            Hour = hour,
            Minute = minute,
            WorkingRange = workingRange,
            Range = workingRange == WorkingRange.Daily ? 0 : range,
            Amount = amount,
            PackageDetailId = packageDetailId,
            Status = status,
        };
    }

    public static Bot Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        int hour,
        int minute,
        WorkingRange workingRange,
        int range,
        int amount,
        int packageDetailId)
    {
        return new Bot()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            Hour = hour,
            Minute = minute,
            WorkingRange = workingRange,
            Range = range,
            Amount = amount,
            PackageDetailId = packageDetailId,
        };
    }
}
