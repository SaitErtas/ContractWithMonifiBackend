using MediatR;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Packages;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetNoBonusPurchasedMovements;

internal class GetNoBonusPurchasedMovementsQueryHandler : IQueryHandler<GetNoBonusPurchasedMovementsQuery, GetNoBonusPurchasedMovementsQueryResponse>
{
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IMediator _mediator;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    public GetNoBonusPurchasedMovementsQueryHandler(IUserQueryDataPort userQueryDataPort, IAccountMovementQueryDataPort accountMovementQueryDataPort, IPackageQueryDataPort packageQueryDataPort, IMediator mediator, IStringLocalizer<Resource> stringLocalizer)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _packageQueryDataPort = packageQueryDataPort;
        _mediator = mediator;
        _userQueryDataPort = userQueryDataPort;
        _stringLocalizer = stringLocalizer;
    }
    public async Task<GetNoBonusPurchasedMovementsQueryResponse> Handle(GetNoBonusPurchasedMovementsQuery request, CancellationToken cancellationToken)
    {
        var purchasedAccountMovementsSingleQueryResponse = new List<GetNoBonusPurchasedMovementsSingleQueryResponse>();
        var accountMovements = await _accountMovementQueryDataPort.GetNoBonusPurchasedMovementAsync(request.UserId);
        var packages = await _packageQueryDataPort.GetsAsync();

        foreach (var accountMovement in accountMovements)
        {
            var package = packages.FirstOrDefault(x => x.Details.Any(y => y.Id == accountMovement.PackageDetail.Id));
            accountMovement.PackageDetail.SetPackage(package);
        }

        purchasedAccountMovementsSingleQueryResponse = accountMovements.Select(x => new GetNoBonusPurchasedMovementsSingleQueryResponse(x, _stringLocalizer)).ToList();

        return new GetNoBonusPurchasedMovementsQueryResponse(purchasedAccountMovementsSingleQueryResponse);
    }
}