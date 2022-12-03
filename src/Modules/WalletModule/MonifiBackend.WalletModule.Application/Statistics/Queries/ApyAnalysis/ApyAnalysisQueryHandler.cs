using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Settings;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.ApyAnalysis;

internal class ApyAnalysisQueryHandler : IQueryHandler<ApyAnalysisQuery, ApyAnalysisQueryResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    public ApyAnalysisQueryHandler(IUserQueryDataPort userQueryDataPort, IAccountMovementQueryDataPort accountMovementQueryDataPort, ISettingQueryDataPort settingQueryDataPort)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _settingQueryDataPort = settingQueryDataPort;
        _userQueryDataPort = userQueryDataPort;
    }
    public async Task<ApyAnalysisQueryResponse> Handle(ApyAnalysisQuery request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetUserAsync(request.UserId);
        var userBonus = await _userQueryDataPort.GetTotalBonusAsync(request.UserId);
        var userNotComission = await _userQueryDataPort.GetNotCommissionTotalSaleAsync(request.UserId);
        var userTotalSale = await _userQueryDataPort.GetTotalSaleAsync(request.UserId);
        var totalEarning = userTotalSale + userBonus;
        decimal percent = 0;
        if (userNotComission != 0)
            percent = (totalEarning / userNotComission) * 100;
        else if (userNotComission == 0)
            percent = totalEarning;


        var movements = await _accountMovementQueryDataPort.GetSaleMovementAsync(request.UserId, TransactionStatus.Successful);
        var firstTime = movements.OrderBy(o => o.TransferTime).FirstOrDefault()?.TransferTime;

        var kazanc = movements.Select(s => new { ExistDate = s.TransferTime.AddMonths(s.PackageDetail.Duration) }).ToList();
        var lastTime = kazanc.OrderByDescending(o => o.ExistDate).FirstOrDefault()?.ExistDate;

        return new ApyAnalysisQueryResponse(user.ReferanceCode, totalEarning, firstTime, lastTime, percent);
    }
}