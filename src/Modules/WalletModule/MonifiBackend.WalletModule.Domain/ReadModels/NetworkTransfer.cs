namespace MonifiBackend.WalletModule.Domain.ReadModels;

public class NetworkTransfer
{
    public NetworkTransfer(decimal amount, string fromAddress, string toAddress, string hash, string network)
    {
        Amount = amount;
        FromAddress = fromAddress;
        ToAddress = toAddress;
        Hash = hash;
        Network = network;
        Id = hash;
    }
    public decimal Amount { get; private set; }
    public string FromAddress { get; private set; }
    public string ToAddress { get; private set; }
    public string Hash { get; private set; }
    public string Network { get; private set; }
    public string ActionCommand { get; } = "select";
    public string Id { get; set; }
}
