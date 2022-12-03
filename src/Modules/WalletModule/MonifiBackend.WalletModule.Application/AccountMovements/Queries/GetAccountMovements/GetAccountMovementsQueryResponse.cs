using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.Core.Infrastructure.Utility;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Packages;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetAccountMovements;

public class GetAccountMovementsQueryResponse
{
    public GetAccountMovementsQueryResponse(List<AccountMovement> accountMovements, IStringLocalizer<Resource> stringLocalizer)
    {
        Movements = accountMovements.Select(x => new GetAccountMovementsSingleQueryResponse(x, stringLocalizer)).ToList();
    }
    public List<GetAccountMovementsSingleQueryResponse> Movements { get; set; }
}
public class GetAccountMovementsSingleQueryResponse
{
    public GetAccountMovementsSingleQueryResponse(AccountMovement accountMovement, IStringLocalizer<Resource> stringLocalizer)
    {
        Id = accountMovement.Id;
        Amount = accountMovement.Amount;
        CreatedAt = accountMovement.CreatedAt;
        BlockEndDate = accountMovement.TransferTime == default(DateTime) ? null : accountMovement.TransferTime.AddMonths(accountMovement.PackageDetail.Duration);
        TransactionStatus = accountMovement.TransactionStatus.ToString();
        TransactionStatusDescription = accountMovement.TransactionStatus.ToTransactionStatusDescription(stringLocalizer);
        ActionType = accountMovement.ActionType.ToActionType(stringLocalizer);
        Wallet = new GetMovementsWalletResponse(accountMovement.Wallet.Id, accountMovement.Wallet.WalletAddress, accountMovement.Wallet.CryptoNetwork);
        PackageDetail = new GetMovementsPackageDetailResponse(accountMovement.PackageDetail.Id, accountMovement.PackageDetail.Name, accountMovement.PackageDetail.Duration, accountMovement.PackageDetail.Commission, accountMovement.PackageDetail.Package);
        TotalDay = BlockEndDate == null ? 0 : BlockEndDate.Value.Subtract(accountMovement.TransferTime).Days;
        RemainDay = BlockEndDate == null ? 0 : BlockEndDate.Value.Subtract(DateTime.Now).Days;
        PassedDay = TotalDay - RemainDay;
        Earning = MathExtensions.PercentageCalculation(accountMovement.Amount, accountMovement.PackageDetail.Commission);
    }

    public int Id { get; set; }
    public decimal Amount { get; set; }
    public string TransactionStatus { get; set; }
    public string TransactionStatusDescription { get; set; }
    public string ActionType { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? BlockEndDate { get; set; }
    public GetMovementsWalletResponse Wallet { get; set; }
    public GetMovementsPackageDetailResponse PackageDetail { get; set; }
    public int RemainDay { get; set; }
    public int TotalDay { get; set; }
    public int PassedDay { get; set; }
    public decimal Earning { get; set; }
}
public class GetMovementsWalletResponse
{
    public GetMovementsWalletResponse(int id, string walletAddress, Network network)
    {
        Id = id;
        WalletAddress = walletAddress;
        Network = new GetMovementsNetworkResponse(network.Id, network.Name);
    }

    public int Id { get; set; }
    public string WalletAddress { get; set; }
    public GetMovementsNetworkResponse Network { get; set; }
}
public class GetMovementsNetworkResponse
{
    public GetMovementsNetworkResponse(int id, string name)
    {
        Id = id;
        Name = name;
    }

    public int Id { get; set; }
    public string Name { get; set; }
}
public class GetMovementsPackageDetailResponse
{
    public GetMovementsPackageDetailResponse(int id, string name, int duration, int commission, Package package)
    {
        Id = id;
        Name = name;
        Duration = duration;
        Commission = commission;
        Package = package == null ? new GetMovementsPackageResponse() : new GetMovementsPackageResponse(package.Id, package.Name, package.MinValue, package.MaxValue, package.ChangePeriodDay);
    }
    public int Id { get; set; }
    public string Name { get; set; }
    public int Duration { get; set; }
    public int Commission { get; set; }
    public GetMovementsPackageResponse Package { get; set; }
}
public class GetMovementsPackageResponse
{
    public GetMovementsPackageResponse()
    {

    }
    public GetMovementsPackageResponse(int id, string name, int minValue, int maxValue, int changePeriodDay)
    {
        Id = id;
        Name = name;
        MinValue = minValue;
        MaxValue = maxValue;
        ChangePeriodDay = changePeriodDay;
    }
    public int Id { get; set; }
    public string Name { get; set; }
    public int MinValue { get; set; }
    public int ChangePeriodDay { get; set; }
    public int MaxValue { get; set; }
}