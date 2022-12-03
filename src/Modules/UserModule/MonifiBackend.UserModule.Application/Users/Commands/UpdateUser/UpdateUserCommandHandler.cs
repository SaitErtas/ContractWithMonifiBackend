using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Accounts;
using MonifiBackend.Core.Domain.BscScans;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.TronNetworks;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Domain.Localizations;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.UserModule.Domain.Wallets;
using System.Globalization;

namespace MonifiBackend.UserModule.Application.Users.Commands.UpdateUser;

internal class UpdateUserCommandHandler : ICommandHandler<UpdateUserCommand, UpdateUserCommandResponse>
{
    private const int BSCSCAN_VALUE = 1;
    private const int TRONNETWORK_VALUE = 2;
    private readonly IWalletQueryDataPort _walletQueryDataPort;
    private readonly ILocalizationQueryDataPort _localizationQueryDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    private readonly IBscScanAccountsDataPort _bscScanAccountsDataPort;
    private readonly ITronNetworkAccountsDataPort _tronNetworkAccountsDataPort;

    public UpdateUserCommandHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, ILocalizationQueryDataPort localizationQueryDataPort, IStringLocalizer<Resource> stringLocalizer, IWalletQueryDataPort walletQueryDataPort, IBscScanAccountsDataPort bscScanAccountsDataPort, ITronNetworkAccountsDataPort tronNetworkAccountsDataPort)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _localizationQueryDataPort = localizationQueryDataPort;
        _stringLocalizer = stringLocalizer;
        _bscScanAccountsDataPort = bscScanAccountsDataPort;
        _tronNetworkAccountsDataPort = tronNetworkAccountsDataPort;
        _walletQueryDataPort = walletQueryDataPort;
    }

    public async Task<UpdateUserCommandResponse> Handle(UpdateUserCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        AppRule.ExistsAndActive(user,
            new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])} UserId: {request.UserId}"));

        var language = await _localizationQueryDataPort.GetLanguageAsync(request.LanguageId);
        var country = await _localizationQueryDataPort.GetCountryAsync(request.CountryId);
        var network = await _walletQueryDataPort.GetNetworkAsync(request.CryptoNetworkId);

        var walletCheck = await _userQueryDataPort.CheckWalletAddressAsync(request.WalletAddress);
        AppRule.True(walletCheck.Id == 0 || walletCheck.Id == user.Id,
            new BusinessValidationException($"{string.Format(_stringLocalizer["AlreadyExist"], _stringLocalizer["Wallet"])}", $"{string.Format(_stringLocalizer["AlreadyExist"], _stringLocalizer["Wallet"])} UserId: {request.UserId}"));


        if (network.Id == BSCSCAN_VALUE)
        {
            var bnbBalanceRequest = new BnbBalanceRequest
            {
                Address = request.WalletAddress,
            };
            var bnbBalance = await _bscScanAccountsDataPort.GetBnbBalanceAsync(bnbBalanceRequest);
            AppRule.True(bnbBalance.Status == "1",
                new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["Wallet"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["Wallet"])} WalletAddress: {request.WalletAddress}"));
        }
        else if (network.Id == TRONNETWORK_VALUE)
        {
            var account = await _tronNetworkAccountsDataPort.GetAccountsAsync(request.WalletAddress);
            AppRule.True(account.Success,
                new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["Wallet"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["Wallet"])} WalletAddress: {request.WalletAddress}"));
        }

        user.Wallet.SetWalletAddress(request.WalletAddress);
        user.Wallet.SetNetwork(network);

        user.SetUsername(request.Username);
        user.SetFullName(request.FullName);
        user.SetCountry(country);
        user.SetLanguage(language);

        if (user.Phones.Any())
            user.Phones.FirstOrDefault().SetPhone(request.Phone);
        else
            user.AddPhone(request.Phone);

        Thread.CurrentThread.CurrentUICulture = new CultureInfo($"{user.Language.ShortName}");

        var status = await _userCommandDataPort.SaveAsync(user);
        AppRule.True<BusinessValidationException>(status);

        return new UpdateUserCommandResponse();
    }
}
