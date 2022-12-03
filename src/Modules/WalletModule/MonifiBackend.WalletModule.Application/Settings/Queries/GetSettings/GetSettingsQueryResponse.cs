using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Application.Settings.Queries.GetSettings;

public class GetSettingsQueryResponse
{
    public GetSettingsQueryResponse(Setting setting)
    {
        MonifiPrice = setting.MonifiPrice;
        BscScanAddress = setting.BscScanAddress;
        TronNetworkAddress = setting.TronNetworkAddress;
        BscScanTokenSymbol = setting.BscScanTokenSymbol;
        TronNetworkTokenSymbol = setting.TronNetworkTokenSymbol;
        MaintenanceMode = setting.MaintenanceMode;
    }
    public decimal MonifiPrice { get; private set; }
    public string BscScanAddress { get; private set; }
    public string TronNetworkAddress { get; private set; }
    public string BscScanTokenSymbol { get; private set; }
    public string TronNetworkTokenSymbol { get; private set; }
    public bool MaintenanceMode { get; private set; }
}
