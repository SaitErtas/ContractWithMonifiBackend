using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Settings;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetAccountActivities;

internal class GetAccountActivitiesQueryHandler : IQueryHandler<GetAccountActivitiesQuery, GetAccountActivitiesQueryResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    public GetAccountActivitiesQueryHandler(IAccountMovementQueryDataPort accountMovementQueryDataPort, ISettingQueryDataPort settingQueryDataPort, IUserQueryDataPort userQueryDataPort)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _settingQueryDataPort = settingQueryDataPort;
        _userQueryDataPort = userQueryDataPort;
    }
    public async Task<GetAccountActivitiesQueryResponse> Handle(GetAccountActivitiesQuery request, CancellationToken cancellationToken)
    {
        var movements = await _accountMovementQueryDataPort.GetAllRealMovementAsync(ActionType.Sale);
        return new GetAccountActivitiesQueryResponse(movements);
    }
}