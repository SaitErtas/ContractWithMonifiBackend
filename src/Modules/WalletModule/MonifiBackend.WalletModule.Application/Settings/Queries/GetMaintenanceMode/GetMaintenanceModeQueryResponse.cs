using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Application.Settings.Queries.GetMaintenanceMode;

public class GetMaintenanceModeQueryResponse
{
    public GetMaintenanceModeQueryResponse(Setting setting)
    {
        MaintenanceMode = setting.MaintenanceMode;
    }
    public bool MaintenanceMode { get; set; }
}
