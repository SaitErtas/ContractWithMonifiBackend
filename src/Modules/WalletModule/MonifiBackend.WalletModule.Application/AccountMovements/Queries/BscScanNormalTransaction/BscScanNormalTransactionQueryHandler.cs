using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Accounts;
using MonifiBackend.Core.Domain.BscScans;
using MonifiBackend.Core.Domain.TronNetworks;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.BscScanNormalTransaction;

internal class BscScanNormalTransactionQueryHandler : IQueryHandler<BscScanNormalTransactionQuery, BscScanNormalTransactionQueryResponse>
{
    private readonly IBscScanAccountsDataPort _bscScanAccountsService;
    private readonly ITronNetworkAccountsDataPort _tronNetworkAccountsDataPort;

    public BscScanNormalTransactionQueryHandler(IBscScanAccountsDataPort bscScanAccountsService, ITronNetworkAccountsDataPort tronNetworkAccountsDataPort)
    {
        _bscScanAccountsService = bscScanAccountsService;
        _tronNetworkAccountsDataPort = tronNetworkAccountsDataPort;
    }
    public async Task<BscScanNormalTransactionQueryResponse> Handle(BscScanNormalTransactionQuery request, CancellationToken cancellationToken)
    {
        var asdasd = await _tronNetworkAccountsDataPort.GetTransfersAsync(request.Address);
        var bnbBalanceRequest = new NormalTransactionsRequest
        {
            Address = request.Address,
        };
        var bnbBalance = await _bscScanAccountsService.GetNormalTransactionsByAddressAsync(bnbBalanceRequest);

        return new BscScanNormalTransactionQueryResponse();
    }
}