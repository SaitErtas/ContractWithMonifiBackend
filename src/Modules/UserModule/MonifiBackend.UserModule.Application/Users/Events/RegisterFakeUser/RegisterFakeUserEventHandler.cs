using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.UserModule.Domain.Localizations;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.UserModule.Domain.Wallets;

namespace MonifiBackend.UserModule.Application.Users.Events.RegisterFakeUser;

internal class RegisterFakeUserEventHandler : IEventHandler<RegisterFakeUserEvent>
{
    private const int DEFAULT_VALUE = 1;
    private readonly IWalletQueryDataPort _walletQueryDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly ILocalizationQueryDataPort _localizationQueryDataPort;
    public RegisterFakeUserEventHandler(IUserQueryDataPort userQueryDataPort, IUserCommandDataPort userCommandDataPort, ILocalizationQueryDataPort localizationQueryDataPort, IWalletQueryDataPort walletQueryDataPort)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _localizationQueryDataPort = localizationQueryDataPort;
        _walletQueryDataPort = walletQueryDataPort;
    }
    public async Task Handle(RegisterFakeUserEvent request, CancellationToken cancellationToken)
    {
        var email = RandomKeyGenerator.RandomKey(6) + "@monifi.io";
        var terms = true;
        var passwordHash = BCrypt.Net.BCrypt.HashPassword("123456");
        var username = RandomKeyGenerator.RandomKey(6);
        var fullName = RandomKeyGenerator.RandomKey(6) + " " + RandomKeyGenerator.RandomKey(6);

        var referanceCode = await GenerateReferanceCode();
        var confirmationCode = await GenerateConfirmationCode();

        var language = await _localizationQueryDataPort.GetLanguageAsync(DEFAULT_VALUE);
        var country = await _localizationQueryDataPort.GetCountryAsync(DEFAULT_VALUE);
        var network = await _walletQueryDataPort.GetNetworkAsync(DEFAULT_VALUE);

        var wallet = Wallet.CreateNew(string.Empty, network);
        var user = User.CreateNew(email, passwordHash, terms, 1, referanceCode, confirmationCode, string.Empty, language, country, wallet, Role.User, BaseStatus.Active);
        user.SetUsername(username);
        user.SetFullName(fullName);
        var userId = await _userCommandDataPort.CreateAsync(user);

    }
    private async Task<string> GenerateReferanceCode()
    {
        string referanceCode;
    TekrarOlustur:
        referanceCode = RandomKeyGenerator.RandomKey(6);
        //Böyle bir referans kodu var mı?
        var isReferanceCode = await _userQueryDataPort.CheckUserReferanceCodeAsync(referanceCode);
        if (!isReferanceCode)
            return referanceCode;
        else
            goto TekrarOlustur;
    }
    private async Task<string> GenerateConfirmationCode()
    {
        string confirmationCode;
    TekrarOlustur:
        confirmationCode = RandomKeyGenerator.RandomKey(6);
        //Böyle bir referans kodu var mı?
        var isConfirmationCode = await _userQueryDataPort.CheckUserConfirmationCodeAsync(confirmationCode);
        if (!isConfirmationCode)
            return confirmationCode;
        else
            goto TekrarOlustur;
    }
}