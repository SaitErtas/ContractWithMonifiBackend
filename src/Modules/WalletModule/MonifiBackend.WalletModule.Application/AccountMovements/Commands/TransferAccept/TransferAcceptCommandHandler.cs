using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Commands.TransferAccept;

internal class TransferAcceptCommandHandler : ICommandHandler<TransferAcceptCommand, TransferAcceptCommandResponse>
{
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IAccountMovementCommandDataPort _accountMovementCommandDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;

    public TransferAcceptCommandHandler(IAccountMovementQueryDataPort accountMovementQueryDataPort, IAccountMovementCommandDataPort accountMovementCommandDataPort, IUserQueryDataPort userQueryDataPort)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _accountMovementCommandDataPort = accountMovementCommandDataPort;
        _userQueryDataPort = userQueryDataPort;
    }

    public async Task<TransferAcceptCommandResponse> Handle(TransferAcceptCommand request, CancellationToken cancellationToken)
    {
        var user = await _userQueryDataPort.GetUserEmailAsync(request.Email);
        var movements = await _accountMovementQueryDataPort.GetAllMovementAsync(user.Id, TransactionStatus.Pending);
        foreach (var movement in movements)
        {
            movement.SetTransactionStatus(TransactionStatus.Successful);
            movement.SetTransferTime(DateTime.Now);
        }
        await _accountMovementCommandDataPort.BulkSaveAsync(movements);

        return new TransferAcceptCommandResponse();
    }
}