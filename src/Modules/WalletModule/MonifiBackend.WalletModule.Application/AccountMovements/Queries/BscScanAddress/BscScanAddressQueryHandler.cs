using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Accounts;
using MonifiBackend.Core.Domain.BscScans;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.BscScanAddress;

internal class BscScanAddressQueryHandler : IQueryHandler<BscScanAddressQuery, BscScanAddressQueryResponse>
{
    private readonly IBscScanAccountsDataPort _bscScanAccountsService;
    public BscScanAddressQueryHandler(IBscScanAccountsDataPort bscScanAccountsService)
    {
        _bscScanAccountsService = bscScanAccountsService;
    }
    public async Task<BscScanAddressQueryResponse> Handle(BscScanAddressQuery request, CancellationToken cancellationToken)
    {
        var bnbBalanceRequest = new BnbBalanceRequest
        {
            Address = request.Address,
        };
        var bnbBalance = await _bscScanAccountsService.GetBnbBalanceAsync(bnbBalanceRequest);

        return new BscScanAddressQueryResponse();
    }
}