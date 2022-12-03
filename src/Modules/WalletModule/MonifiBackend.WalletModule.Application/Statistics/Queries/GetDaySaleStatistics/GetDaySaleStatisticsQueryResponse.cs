using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetDaySaleStatistics;

public class GetDaySaleStatisticsQueryResponse
{
    public GetDaySaleStatisticsQueryResponse(List<DaySaleStatistics> daySaleStatistics, decimal totalSale, decimal totalBonus, decimal percentageofChange, Setting setting)
    {
        DaySaleStatistics = daySaleStatistics.Select(x => new GetDaySaleStatisticQueryResponse(x, setting)).ToList();
        TotalMonifi = totalSale / setting.MonifiPrice;
        PercentageofChange = percentageofChange;
    }
    public decimal PercentageofChange { get; set; }
    public decimal TotalMonifi { get; set; }
    public List<GetDaySaleStatisticQueryResponse> DaySaleStatistics { get; set; }
}
public class GetDaySaleStatisticQueryResponse
{
    public GetDaySaleStatisticQueryResponse(DaySaleStatistics daySaleStatistic, Setting setting)
    {
        Day = daySaleStatistic.Day;
        TotalSales = daySaleStatistic.TotalSales / setting.MonifiPrice;

        Name = Day.ToString("dd/MM");
        Pv = TotalSales;
    }
    public DateTime Day { get; set; }
    public decimal TotalSales { get; set; }
    public string Name { get; set; }
    public decimal Pv { get; set; }
}
