using MediatR;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Packages;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetAccountMovements;

internal class GetAccountMovementsQueryHandler : IQueryHandler<GetAccountMovementsQuery, GetAccountMovementsQueryResponse>
{
    private readonly IMediator _mediator;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    public GetAccountMovementsQueryHandler(IAccountMovementQueryDataPort accountMovementQueryDataPort, IPackageQueryDataPort packageQueryDataPort, IMediator mediator, IStringLocalizer<Resource> stringLocalizer)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _packageQueryDataPort = packageQueryDataPort;
        _mediator = mediator;
        _stringLocalizer = stringLocalizer;
    }
    public async Task<GetAccountMovementsQueryResponse> Handle(GetAccountMovementsQuery request, CancellationToken cancellationToken)
    {

        var accountMovements = await _accountMovementQueryDataPort.GetAccountMovementsAsync(request.UserId);
        var packages = await _packageQueryDataPort.GetsAsync();

        foreach (var accountMovement in accountMovements)
        {
            var package = packages.FirstOrDefault(x => x.Details.Any(y => y.Id == accountMovement.PackageDetail.Id));
            accountMovement.PackageDetail.SetPackage(package);
        }

        return new GetAccountMovementsQueryResponse(accountMovements, _stringLocalizer);
    }
}