using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Settings;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetAdminStatistics;

internal class GetAdminStatisticsQueryHandler : IQueryHandler<GetAdminStatisticsQuery, GetAdminStatisticsQueryResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    public GetAdminStatisticsQueryHandler(IAccountMovementQueryDataPort accountMovementQueryDataPort, ISettingQueryDataPort settingQueryDataPort, IUserQueryDataPort userQueryDataPort)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _settingQueryDataPort = settingQueryDataPort;
        _userQueryDataPort = userQueryDataPort;
    }
    public async Task<GetAdminStatisticsQueryResponse> Handle(GetAdminStatisticsQuery request, CancellationToken cancellationToken)
    {
        var totalSale = await _accountMovementQueryDataPort.GetTotalSaleAsync();
        var totalBonus = await _accountMovementQueryDataPort.GetTotalBonusAsync();
        var setting = await _settingQueryDataPort.GetAsync(DEFAULT_SETTING_VALUE);
        var userCount = await _userQueryDataPort.GetUserCountAsync();

        return new GetAdminStatisticsQueryResponse(setting, totalSale, totalBonus, userCount);
    }
}