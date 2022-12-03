using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Application.Settings.Queries.GetMaintenanceMode;

internal class GetMaintenanceModeQueryHandler : IQueryHandler<GetMaintenanceModeQuery, GetMaintenanceModeQueryResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    public GetMaintenanceModeQueryHandler(ISettingQueryDataPort settingQueryDataPort)
    {
        _settingQueryDataPort = settingQueryDataPort;
    }
    public async Task<GetMaintenanceModeQueryResponse> Handle(GetMaintenanceModeQuery request, CancellationToken cancellationToken)
    {
        var setting = await _settingQueryDataPort.GetAsync(DEFAULT_SETTING_VALUE);

        return new GetMaintenanceModeQueryResponse(setting);
    }
}