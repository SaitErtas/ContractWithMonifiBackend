using MediatR;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Packages;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetPurchasedMovements;

internal class GetPurchasedMovementsQueryHandler : IQueryHandler<GetPurchasedMovementsQuery, GetPurchasedMovementsQueryResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IMediator _mediator;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    public GetPurchasedMovementsQueryHandler(IUserQueryDataPort userQueryDataPort, IAccountMovementQueryDataPort accountMovementQueryDataPort, IPackageQueryDataPort packageQueryDataPort, IMediator mediator, IStringLocalizer<Resource> stringLocalizer)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _packageQueryDataPort = packageQueryDataPort;
        _mediator = mediator;
        _userQueryDataPort = userQueryDataPort;
        _stringLocalizer = stringLocalizer;
    }
    public async Task<GetPurchasedMovementsQueryResponse> Handle(GetPurchasedMovementsQuery request, CancellationToken cancellationToken)
    {
        var purchasedAccountMovementsSingleQueryResponse = new List<GetPurchasedAccountMovementsSingleQueryResponse>();
        var accountMovements = await _accountMovementQueryDataPort.GetPurchasedMovementAsync(request.UserId);
        var packages = await _packageQueryDataPort.GetsAsync();

        foreach (var accountMovement in accountMovements)
        {
            var package = packages.FirstOrDefault(x => x.Details.Any(y => y.Id == accountMovement.PackageDetail.Id));
            accountMovement.PackageDetail.SetPackage(package);
        }

        purchasedAccountMovementsSingleQueryResponse = accountMovements.Select(x => new GetPurchasedAccountMovementsSingleQueryResponse(x, _stringLocalizer)).ToList();

        var user = await _userQueryDataPort.GetUserAsync(request.UserId);
        var meFirstNetworkUsers = await _userQueryDataPort.GetMeFirstNetworkAsync(user.Id);

        var networkUserIds = meFirstNetworkUsers.Select(x => x.Id).ToList();
        var networkUsers = await _userQueryDataPort.GetAllNetworkAsync(networkUserIds);
        foreach (var networkUser in networkUsers)
        {
            var networkAccountMovements = await _accountMovementQueryDataPort.GetAccountMovementsAsync(networkUser.Id);
            foreach (var networkAccountMovement in networkAccountMovements)
            {
                var package = packages.FirstOrDefault(x => x.Details.Any(y => y.Id == networkAccountMovement.PackageDetail.Id));
                networkAccountMovement.PackageDetail.SetPackage(package);
                purchasedAccountMovementsSingleQueryResponse.Add(new GetPurchasedAccountMovementsSingleQueryResponse(networkAccountMovement.Id, networkUser.FullName, true, networkAccountMovement.Amount, networkAccountMovement.CreatedAt, networkAccountMovement.TransferTime, networkAccountMovement.TransactionStatus, networkAccountMovement.ActionType, networkAccountMovement.Wallet.Id, networkAccountMovement.Wallet.WalletAddress, networkAccountMovement.Wallet.CryptoNetwork, networkAccountMovement.PackageDetail.Id, networkAccountMovement.PackageDetail.Name, networkAccountMovement.PackageDetail.Duration, networkAccountMovement.PackageDetail.Commission, package, _stringLocalizer));
            }
        }

        return new GetPurchasedMovementsQueryResponse(purchasedAccountMovementsSingleQueryResponse);
    }
}