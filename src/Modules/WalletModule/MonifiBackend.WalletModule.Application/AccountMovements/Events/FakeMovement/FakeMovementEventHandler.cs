using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Bots;
using MonifiBackend.WalletModule.Domain.Packages;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Events.FakeMovement;

internal class FakeMovementEventHandler : IEventHandler<FakeMovementEvent>
{
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IAccountMovementCommandDataPort _accountMovementCommandDataPort;
    private readonly IBotQueryDataPort _botQueryDataPort;
    public FakeMovementEventHandler(IUserQueryDataPort userQueryDataPort, IPackageQueryDataPort packageQueryDataPort, IAccountMovementCommandDataPort accountMovementCommandDataPort, IBotQueryDataPort botQueryDataPort)
    {
        _packageQueryDataPort = packageQueryDataPort;
        _userQueryDataPort = userQueryDataPort;
        _accountMovementCommandDataPort = accountMovementCommandDataPort;
        _botQueryDataPort = botQueryDataPort;
    }
    public async Task Handle(FakeMovementEvent request, CancellationToken cancellationToken)
    {
        DateTime now = DateTime.Now;
        var nowDayOfWeek = ((int)now.DayOfWeek);
        int nowHour = now.Hour;
        int nowMinute = now.Minute;
        var bots = await _botQueryDataPort.GetActiveAsync();
        foreach (var bot in bots)
        {
            if ((nowHour == bot.Hour && nowMinute == bot.Minute) && ((bot.WorkingRange == WorkingRange.Weekly && bot.Range == nowDayOfWeek) || bot.WorkingRange == WorkingRange.Daily))
            {
                await sellMovement(bot.PackageDetailId, bot.Amount);
            }
        }
    }
    private async Task sellMovement(int packageDetailId, decimal amount)
    {
        var user = await _userQueryDataPort.GetRandomMonifiUser();
        var packageDetail = await _packageQueryDataPort.GetPackageDetailAsync(packageDetailId);
        var movement = AccountMovement.CreateNew(amount, BaseStatus.Active, TransactionStatus.Successful, ActionType.Sale, packageDetail, user.Wallet, "Monifi", string.Empty, DateTime.UtcNow);
        user.Wallet.AddMovement(movement);
        var result = await _accountMovementCommandDataPort.SaveAsync(user.Wallet);
    }
}
