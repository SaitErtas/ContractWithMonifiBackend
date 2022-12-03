using MonifiBackend.WalletModule.Domain.AccountMovements;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetAccountActivities;

public class GetAccountActivitiesQueryResponse
{
    public GetAccountActivitiesQueryResponse(List<AccountMovement> movements)
    {
        Movements = movements.Select(s => new GetAccountActivitiQueryResponse(s)).ToList();
    }
    public List<GetAccountActivitiQueryResponse> Movements { get; private set; }
}
public class GetAccountActivitiQueryResponse
{
    public GetAccountActivitiQueryResponse(AccountMovement movement)
    {
        Username = movement.Wallet.User.Username;
        FullName = movement.Wallet.User.FullName;
        Email = movement.Wallet.User.Email;
        WalletAddress = movement.Wallet.WalletAddress;
        CryptoNetwork = movement.Wallet.CryptoNetwork.Name;
        Amount = movement.Amount;
        TransactionStatus = movement.TransactionStatus.ToString();
        ActionType = movement.ActionType.ToString();
        Hash = movement.Hash;
        TokenSymbol = movement.TokenSymbol;
        PackageName = movement.PackageDetail.Package.Name;
        Duration = movement.PackageDetail.Duration;
        TransferTime = movement.TransferTime;
        TransferTime = movement.TransferTime;
        Id = movement.Id;
    }
    public string Username { get; private set; }
    public string FullName { get; private set; }
    public string Email { get; private set; }
    public string WalletAddress { get; private set; }
    public string CryptoNetwork { get; private set; }
    public decimal Amount { get; private set; }
    public string TransactionStatus { get; private set; }
    public string ActionType { get; private set; }
    public string Hash { get; private set; }
    public string TokenSymbol { get; private set; }
    public string PackageName { get; private set; }
    public int Duration { get; private set; }
    public DateTime TransferTime { get; private set; }
    public int Id { get; private set; }
    public string ActionCommand { get; private set; } = "select";
}