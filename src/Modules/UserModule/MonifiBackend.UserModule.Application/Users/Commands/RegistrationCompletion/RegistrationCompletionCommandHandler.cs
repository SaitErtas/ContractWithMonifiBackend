using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Accounts;
using MonifiBackend.Core.Domain.BscScans;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.TronNetworks;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Domain.Localizations;
using MonifiBackend.UserModule.Domain.Notifications;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.UserModule.Domain.Wallets;
using System.Globalization;

namespace MonifiBackend.UserModule.Application.Users.Commands.RegistrationCompletion;

internal class RegistrationCompletionCommandHandler : ICommandHandler<RegistrationCompletionCommand, RegistrationCompletionCommandResponse>
{
    private const int BSCSCAN_VALUE = 1;
    private const int TRONNETWORK_VALUE = 2;
    private readonly IWalletQueryDataPort _walletQueryDataPort;
    private readonly ILocalizationQueryDataPort _localizationQueryDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IBscScanAccountsDataPort _bscScanAccountsDataPort;
    private readonly ITronNetworkAccountsDataPort _tronNetworkAccountsDataPort;
    private readonly INotificationCommandDataPort _notificationCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public RegistrationCompletionCommandHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, ILocalizationQueryDataPort localizationQueryDataPort, IWalletQueryDataPort walletQueryDataPort, IBscScanAccountsDataPort bscScanAccountsDataPort, ITronNetworkAccountsDataPort tronNetworkAccountsDataPort, IStringLocalizer<Resource> stringLocalizer, INotificationCommandDataPort notificationCommandDataPort)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _localizationQueryDataPort = localizationQueryDataPort;
        _walletQueryDataPort = walletQueryDataPort;
        _bscScanAccountsDataPort = bscScanAccountsDataPort;
        _tronNetworkAccountsDataPort = tronNetworkAccountsDataPort;
        _stringLocalizer = stringLocalizer;
        _notificationCommandDataPort = notificationCommandDataPort;
    }

    public async Task<RegistrationCompletionCommandResponse> Handle(RegistrationCompletionCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetAsync(request.UserId);
        AppRule.ExistsAndActive(user,
            new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])} UserId: {request.UserId}"));
        AppRule.True(string.IsNullOrEmpty(user.Wallet.WalletAddress),
            new BusinessValidationException($"{_stringLocalizer["UserAlreadySubscribed"]}", $"{_stringLocalizer["UserAlreadySubscribed"]} UserId: {request.UserId}"));

        var language = await _localizationQueryDataPort.GetLanguageAsync(request.LanguageId);
        var country = await _localizationQueryDataPort.GetCountryAsync(request.CountryId);
        var network = await _walletQueryDataPort.GetNetworkAsync(request.CryptoNetworkId);

        var walletCheck = await _userQueryDataPort.CheckWalletAddressAsync(request.WalletAddress);
        AppRule.False(walletCheck.IsExist(),
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
        user.AddNotification($"{_stringLocalizer["NewRegister"]}", user.FullName, default(decimal));

        var status = await _userCommandDataPort.SaveAsync(user);
        AppRule.True<BusinessValidationException>(status);

        var notification = Notification.CreateNew(user.ReferanceUser, $"{string.Format(_stringLocalizer["NewRegisterReferanceUser"], user.FullName)}", user.FullName, default(decimal));
        await _notificationCommandDataPort.SaveAsync(notification);

        return new RegistrationCompletionCommandResponse();
    }
}