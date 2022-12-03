using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Application.Settings.Queries.GetSettings;

internal class GetSettingsQueryHandler : IQueryHandler<GetSettingsQuery, GetSettingsQueryResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    public GetSettingsQueryHandler(ISettingQueryDataPort settingQueryDataPort)
    {
        _settingQueryDataPort = settingQueryDataPort;
    }
    public async Task<GetSettingsQueryResponse> Handle(GetSettingsQuery request, CancellationToken cancellationToken)
    {
        var setting = await _settingQueryDataPort.GetAsync(DEFAULT_SETTING_VALUE);

        return new GetSettingsQueryResponse(setting);
    }
}