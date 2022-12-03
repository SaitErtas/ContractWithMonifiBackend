namespace MonifiBackend.Core.Infrastructure.Environments;

public class BscScanConfiguration : IBscScanConfiguration
{
    /// <inheritdoc />
    public BscScanOptions BscScanOptions { get; set; } = new BscScanOptions();
}

public class BscScanOptions
{
    /// <summary>
    /// Api-Key Token from BscScan Account
    /// </summary>
    public string Token { get; set; } = "ZXD3CX98EJ2C5MIDYFPQJB6SKQ1BVJY1D934"; //default token

    /// <summary>
    /// BscScan API domain
    ///  Ex: https://api.bscscan.com/api for main network
    ///      https://api-testnet.bscscan.com/  for test network
    /// </summary>
    public string Uri { get; set; } = "https://api.bscscan.com/api"; // default main net Uri
}

/// <summary>
/// BscScan Configuration Interface
/// </summary>
public interface IBscScanConfiguration
{
    /// <summary>
    /// BscScan Options
    /// </summary>
    BscScanOptions BscScanOptions { get; }
}