using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.WalletModule.Domain.Settings;

public sealed class Setting : ReadOnlyBaseDomain<int>
{
    public string Name { get; private set; }
    public long MaximumSalesQuantity { get; private set; }
    public long MaximumDistributedAPY { get; private set; }
    public long MaximumReferenceBonus { get; private set; }
    public long TotalPreSaleQuantity { get; private set; }
    public decimal MonifiPrice { get; private set; }
    public string BscScanAddress { get; private set; }
    public string TronNetworkAddress { get; private set; }
    public string BscScanTokenSymbol { get; private set; }
    public string TronNetworkTokenSymbol { get; private set; }
    public bool MaintenanceMode { get; private set; }

    public void SetMonifiPrice(decimal monifiPrice) => MonifiPrice = monifiPrice;
    public void SetBscScanAddress(string bscScanAddress) => BscScanAddress = bscScanAddress;
    public void SetTronNetworkAddress(string tronNetworkAddress) => TronNetworkAddress = tronNetworkAddress;
    public void SetBscScanTokenSymbol(string bscScanTokenSymbol) => BscScanTokenSymbol = bscScanTokenSymbol;
    public void SetTronNetworkTokenSymbol(string tronNetworkTokenSymbol) => TronNetworkTokenSymbol = tronNetworkTokenSymbol;
    public static Setting Default() => new();

    public static Setting Map(
        int id,
        BaseStatus status,
        DateTime createdAt,
        DateTime modifiedAt,
        string name,
        long maximumSalesQuantity,
        long maximumDistributedAPY,
        long maximumReferenceBonus,
        long totalPreSaleQuantity,
        decimal monifiPrice,
        bool maintenanceMode,
        string bscScanAddress,
        string tronNetworkAddress,
        string bscScanTokenSymbol,
        string tronNetworkTokenSymbol)
    {
        return new Setting()
        {
            Id = id,
            Status = status,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            Name = name,
            MaximumSalesQuantity = maximumSalesQuantity,
            MaximumDistributedAPY = maximumDistributedAPY,
            MaximumReferenceBonus = maximumReferenceBonus,
            TotalPreSaleQuantity = totalPreSaleQuantity,
            MonifiPrice = monifiPrice,
            MaintenanceMode = maintenanceMode,
            BscScanAddress = bscScanAddress,
            TronNetworkAddress = tronNetworkAddress,
            BscScanTokenSymbol = bscScanTokenSymbol,
            TronNetworkTokenSymbol = tronNetworkTokenSymbol
        };
    }
}