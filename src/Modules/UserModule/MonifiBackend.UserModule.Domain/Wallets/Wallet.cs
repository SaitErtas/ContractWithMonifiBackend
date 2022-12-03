using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.UserModule.Domain.Wallets;

public sealed class Wallet : BaseActivityDomain<int>
{
    private Wallet() { }
    public string WalletAddress { get; private set; }
    public Network CryptoNetwork { get; private set; }

    public void SetWalletAddress(string walletAddress)
    {
        WalletAddress = walletAddress;
    }
    public void SetNetwork(Network network)
    {
        CryptoNetwork = network;
    }
    public static Wallet CreateNew(string walletAddress, Network cryptoNetwork)
    {
        return new Wallet()
        {
            WalletAddress = walletAddress,
            CryptoNetwork = cryptoNetwork
        };
    }

    public static Wallet Default() => new();

    public static Wallet Map(
        int id,
        BaseStatus status,
        string walletAddress,
        Network cryptoNetwork,
        DateTime createdAt,
        DateTime modifiedAt)
    {
        return new Wallet()
        {
            Id = id,
            Status = status,
            WalletAddress = walletAddress,
            CryptoNetwork = cryptoNetwork,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt
        };
    }
}