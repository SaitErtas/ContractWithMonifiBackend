using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetStatistic;

public class GetStatisticsQueryResponse
{
    public GetStatisticsQueryResponse(Setting setting, decimal totalSale, decimal totalBonus, int userCount, int referanceCount)
    {
        MaximumSalesQuantity = setting.MaximumSalesQuantity;
        MaximumDistributedAPY = setting.MaximumDistributedAPY;
        MaximumReferenceBonus = setting.MaximumReferenceBonus;
        TotalPreSaleQuantity = setting.TotalPreSaleQuantity;
        MonifiPrice = setting.MonifiPrice;
        TotalSale = totalSale;
        TotalBonus = totalBonus;
        TotalDistributedMonifi = (totalSale / setting.MonifiPrice) + (totalBonus / setting.MonifiPrice);
        UserCount = userCount;
        ReferanceCount = referanceCount;
        RemainderMonifi = setting.TotalPreSaleQuantity - TotalDistributedMonifi;
    }
    public long MaximumSalesQuantity { get; private set; }
    public long MaximumDistributedAPY { get; private set; }
    public long MaximumReferenceBonus { get; private set; }
    public long TotalPreSaleQuantity { get; private set; }
    public decimal MonifiPrice { get; private set; }
    public decimal TotalSale { get; private set; }
    public decimal TotalBonus { get; private set; }
    public decimal TotalDistributedMonifi { get; private set; }
    public int UserCount { get; private set; }
    public int ReferanceCount { get; private set; }
    public decimal RemainderMonifi { get; private set; }
}
