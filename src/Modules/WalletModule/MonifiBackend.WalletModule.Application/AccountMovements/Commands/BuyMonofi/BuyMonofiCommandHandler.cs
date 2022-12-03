using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Notifications;
using MonifiBackend.WalletModule.Domain.Packages;
using MonifiBackend.WalletModule.Domain.Settings;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Commands.BuyMonofi;

internal class BuyMonofiCommandHandler : ICommandHandler<BuyMonofiCommand, BuyMonofiCommandResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IAccountMovementCommandDataPort _accountMovementCommandDataPort;
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    private readonly INotificationCommandDataPort _notificationCommandDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;

    public BuyMonofiCommandHandler(IUserQueryDataPort userQueryDataPort, IAccountMovementQueryDataPort accountMovementQueryDataPort, IAccountMovementCommandDataPort accountMovementCommandDataPort, IPackageQueryDataPort packageQueryDataPort, ISettingQueryDataPort settingQueryDataPort, IStringLocalizer<Resource> stringLocalizer, INotificationCommandDataPort notificationCommandDataPort)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _accountMovementCommandDataPort = accountMovementCommandDataPort;
        _packageQueryDataPort = packageQueryDataPort;
        _settingQueryDataPort = settingQueryDataPort;
        _stringLocalizer = stringLocalizer;
        _notificationCommandDataPort = notificationCommandDataPort;
        _userQueryDataPort = userQueryDataPort;
    }

    public async Task<BuyMonofiCommandResponse> Handle(BuyMonofiCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetUserAsync(request.UserId);
        AppRule.ExistsAndActive(user,
            new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["User"])} UserId: {request.UserId}"));
        AppRule.False(string.IsNullOrEmpty(user.Wallet.WalletAddress),
            new BusinessValidationException($"{string.Format(_stringLocalizer["FieldRequired"], _stringLocalizer["Wallet"])}", $"{_stringLocalizer["FieldRequired"]} UserId: {request.UserId}"));

        var isIPAdress = await _userQueryDataPort.GetCheckUserIpAsync(request.UserId, request.IpAddress);
        AppRule.False(isIPAdress, new BusinessValidationException($"{_stringLocalizer["SellIPAlreadyExist"]}", $"{_stringLocalizer["SellIPAlreadyExist"]} IpAddress: {request.IpAddress}"));


        var setting = await _settingQueryDataPort.GetAsync(DEFAULT_SETTING_VALUE);
        var totalSale = await _accountMovementQueryDataPort.GetTotalSaleAsync();
        var totalBonus = await _accountMovementQueryDataPort.GetTotalBonusAsync();
        AppRule.True(totalSale < setting.MaximumSalesQuantity,
            new BusinessValidationException($"{_stringLocalizer["PreSaleMaxLimit"]}", $"{_stringLocalizer["PreSaleMaxLimit"]} UserId: {request.UserId}"));
        AppRule.True(totalBonus < setting.MaximumReferenceBonus,
            new BusinessValidationException($"{_stringLocalizer["PreSaleMaxLimit"]}", $"{_stringLocalizer["PreSaleMaxLimit"]} UserId: {request.UserId}"));
        AppRule.True((totalBonus + totalSale) < setting.TotalPreSaleQuantity,
            new BusinessValidationException($"{_stringLocalizer["PreSaleMaxLimit"]}", $"{_stringLocalizer["PreSaleMaxLimit"]} UserId: {request.UserId}"));

        //Seçilen Paket Var Mı Kontrol et?
        var package = await _packageQueryDataPort.GetPackageDetailIdAsync(request.PackageDetailId);
        AppRule.ExistsAndActive(package,
            new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["Package"])}", $"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["Package"])} Package: {request.PackageDetailId}"));
        AppRule.True(package.MinValue <= request.Amount,
            new BusinessValidationException($"{string.Format(_stringLocalizer["OutOfRange"], _stringLocalizer["Package"])}", $"{string.Format(_stringLocalizer["OutOfRange"], _stringLocalizer["Package"])} Package: {request.PackageDetailId}"));
        AppRule.True(package.MaxValue >= request.Amount,
            new BusinessValidationException($"{string.Format(_stringLocalizer["OutOfRange"], _stringLocalizer["Package"])}", $"{string.Format(_stringLocalizer["OutOfRange"], _stringLocalizer["Package"])} Package: {request.PackageDetailId}"));

        var wallet = await _accountMovementQueryDataPort.GetUserWalletAsync(request.UserId);
        var accountMovements = await _accountMovementQueryDataPort.GetAllMovementAsync(request.UserId, TransactionStatus.Pending);
        AppRule.False(accountMovements.Any(a => a.Status == Core.Domain.Base.BaseStatus.Active),
            new BusinessValidationException($"{_stringLocalizer["PendingOrder"]}", $"{_stringLocalizer["PendingOrder"]} UserId: {request.UserId}"));

        //Seçilen Paket ve Miktarı Hesap Haraketlerine ActionType Sale TransactionStatus Pending olarak kaydet
        var movement = AccountMovement.CreateNew(request.Amount, Core.Domain.Base.BaseStatus.Active, TransactionStatus.Pending, ActionType.Sale, package.Details.FirstOrDefault(x => x.Id == request.PackageDetailId), wallet, string.Empty, string.Empty, default(DateTime));
        wallet.AddMovement(movement);
        //Referans Olan Kişiye ActionType Bonus olarak paket ayı kadar hesap hareketi ekle

        var result = await _accountMovementCommandDataPort.SaveAsync(wallet);
        AppRule.True(result, new BusinessValidationException($"{string.Format(_stringLocalizer["NotCreated"], _stringLocalizer["AccountMovement"])}", $"{string.Format(_stringLocalizer["NotCreated"], _stringLocalizer["AccountMovement"])} UserId: {request.UserId}"));

        var notification = Notification.CreateNew(request.UserId, $"{_stringLocalizer["TransactionCheck"]}", user.FullName, default(decimal));
        await _notificationCommandDataPort.SaveAsync(notification);

        return new BuyMonofiCommandResponse();
    }
}
