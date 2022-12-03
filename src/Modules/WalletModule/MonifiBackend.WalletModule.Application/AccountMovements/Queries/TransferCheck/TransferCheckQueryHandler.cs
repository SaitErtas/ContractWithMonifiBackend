using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.BscScans;
using MonifiBackend.Core.Domain.BscScans.Accounts;
using MonifiBackend.Core.Domain.TronNetworks;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Notifications;
using MonifiBackend.WalletModule.Domain.Packages;
using MonifiBackend.WalletModule.Domain.ReadModels;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.TransferCheck;

internal class TransferCheckQueryHandler : IQueryHandler<TransferCheckQuery, TransferCheckQueryResponse>
{
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IAccountMovementCommandDataPort _accountMovementCommandDataPort;
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly IBscScanAccountsDataPort _bscScanAccountsDataPort;
    private readonly ITronNetworkAccountsDataPort _tronNetworkAccountsDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly INotificationCommandDataPort _notificationCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    private const int BSCSCAN_VALUE = 1;
    private const int TRONNETWORK_VALUE = 2;
    private const string BSCSCAN_ADDRESS = "0x292EC45AAE11525E6f3c0115Aa3aC3A27cB250c0";//TODO: database setting
    private const string BSCSCAN_TOKEN_SYMBOL = "BSC-USD";//TODO: database setting
    private const string TRONNETWORK_ADDRESS = "TTkPhAy9WbpRCVBzS4KYFsRGiKL61ygLVG";//TODO: database setting
    private const string TRON_TOKEN_SYMBOL = "USDT";//TODO: database setting
    public TransferCheckQueryHandler(IAccountMovementQueryDataPort accountMovementQueryDataPort, IAccountMovementCommandDataPort accountMovementCommandDataPort, IPackageQueryDataPort packageQueryDataPort, IBscScanAccountsDataPort bscScanAccountsDataPort, ITronNetworkAccountsDataPort tronNetworkAccountsDataPort, IUserQueryDataPort userQueryDataPort, INotificationCommandDataPort notificationCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _accountMovementCommandDataPort = accountMovementCommandDataPort;
        _packageQueryDataPort = packageQueryDataPort;
        _bscScanAccountsDataPort = bscScanAccountsDataPort;
        _tronNetworkAccountsDataPort = tronNetworkAccountsDataPort;
        _userQueryDataPort = userQueryDataPort;
        _notificationCommandDataPort = notificationCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }
    public async Task<TransferCheckQueryResponse> Handle(TransferCheckQuery request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetUserEmailAsync(request.Email);
        var networkTransfers = new List<NetworkTransfer>();
        if (user.Wallet.CryptoNetwork.Id == BSCSCAN_VALUE)
        {
            var bep20TokenTransferEventsRequest = new Bep20TokenTransferEventsRequest
            {
                Address = user.Wallet.WalletAddress
            };
            var bep20TokenTransferEventsResult = await _bscScanAccountsDataPort.GetBep20TokenTransferEventsByAddressAsync(bep20TokenTransferEventsRequest);
            var appropriateTransfers = bep20TokenTransferEventsResult.Result.Where(w =>
            w.To.ToLower() == BSCSCAN_ADDRESS.ToLower() &&
            w.TokenSymbol == BSCSCAN_TOKEN_SYMBOL).Select(s => new NetworkTransfer(IntToDec(s.Value, s.TokenDecimal), s.From, s.To, s.Hash, "BSCSCAN")).ToList();
            networkTransfers.AddRange(appropriateTransfers);
        }
        else if (user.Wallet.CryptoNetwork.Id == TRONNETWORK_VALUE)
        {
            var tronTransfers = await _tronNetworkAccountsDataPort.GetTransfersAsync(user.Wallet.WalletAddress);
            var appropriateTransfers = tronTransfers.TokenTransfers.Where(x =>
                x.ToAddress.ToLower() == TRONNETWORK_ADDRESS.ToLower() &&
                x.TokenInfo.TokenAbbr == TRON_TOKEN_SYMBOL &&
                x.Confirmed == true).Select(s => new NetworkTransfer(IntToDec(s.Quant, s.TokenInfo.TokenDecimal.ToString()), s.FromAddress, s.ToAddress, s.TransactionId, "TRONNETWORK")).ToList();
            networkTransfers.AddRange(appropriateTransfers);
        }


        return new TransferCheckQueryResponse(networkTransfers);
    }
    private decimal IntToDec(string x, string powBy)
    {
        return Decimal.Parse(x) / (decimal)Math.Pow(10.00, Convert.ToInt16(powBy));
    }
}
