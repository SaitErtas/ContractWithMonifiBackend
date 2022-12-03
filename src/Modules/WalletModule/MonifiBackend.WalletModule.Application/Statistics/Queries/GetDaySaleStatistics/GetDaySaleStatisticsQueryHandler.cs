using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetDaySaleStatistics;

internal class GetDaySaleStatisticsQueryHandler : IQueryHandler<GetDaySaleStatisticsQuery, GetDaySaleStatisticsQueryResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    public GetDaySaleStatisticsQueryHandler(IAccountMovementQueryDataPort accountMovementQueryDataPort, ISettingQueryDataPort settingQueryDataPort)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _settingQueryDataPort = settingQueryDataPort;
    }
    public async Task<GetDaySaleStatisticsQueryResponse> Handle(GetDaySaleStatisticsQuery request, CancellationToken cancellationToken)
    {
        var dayOfSales = await _accountMovementQueryDataPort.GetDayOfSalesAsync();
        var totalSale = await _accountMovementQueryDataPort.GetTotalSaleAsync();
        var totalBonus = await _accountMovementQueryDataPort.GetTotalBonusAsync();
        var setting = await _settingQueryDataPort.GetAsync(DEFAULT_SETTING_VALUE);


        var today = DateTime.Now.Date;
        var yesterday = DateTime.Now.AddDays(-1).Date;

        var todaySale = dayOfSales.FirstOrDefault(x => x.Day == today);
        var yesterdaySale = dayOfSales.FirstOrDefault(x => x.Day == yesterday);
        var percentageofChange = 100m;
        if (yesterdaySale.TotalSales != 0)
            percentageofChange = (((todaySale.TotalSales - yesterdaySale.TotalSales) / yesterdaySale.TotalSales)) * 100;

        return new GetDaySaleStatisticsQueryResponse(dayOfSales, totalSale, totalBonus, percentageofChange, setting);
    }
}