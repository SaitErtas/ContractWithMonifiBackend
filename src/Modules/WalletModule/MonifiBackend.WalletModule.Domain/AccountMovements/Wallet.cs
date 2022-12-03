using MonifiBackend.Core.Domain.Base;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Domain.AccountMovements;

public sealed class Wallet : BaseActivityDomain<int>
{
    private Wallet() { }
    public int UserId { get; private set; }
    public User User { get; private set; }
    public string WalletAddress { get; private set; }
    public Network CryptoNetwork { get; private set; }

    private List<AccountMovement> _movements = new();
    public IReadOnlyCollection<AccountMovement> Movements => _movements.AsReadOnly();

    public void AddMovement(AccountMovement movement)
    {
        _movements.Add(movement);
    }
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
        DateTime modifiedAt,
        int userId,
        User user)
    {
        return new Wallet()
        {
            Id = id,
            Status = status,
            WalletAddress = walletAddress,
            CryptoNetwork = cryptoNetwork,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            UserId = userId,
            User = user
        };
    }
}
