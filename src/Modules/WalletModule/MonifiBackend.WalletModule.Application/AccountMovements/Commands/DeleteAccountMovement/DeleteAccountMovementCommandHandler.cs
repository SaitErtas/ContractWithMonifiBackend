using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.WalletModule.Domain.AccountMovements;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Commands.DeleteAccountMovement;

internal class DeleteAccountMovementCommandHandler : ICommandHandler<DeleteAccountMovementCommand, DeleteAccountMovementCommandResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IAccountMovementCommandDataPort _accountMovementCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public DeleteAccountMovementCommandHandler(IAccountMovementQueryDataPort accountMovementQueryDataPort, IAccountMovementCommandDataPort accountMovementCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _accountMovementCommandDataPort = accountMovementCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<DeleteAccountMovementCommandResponse> Handle(DeleteAccountMovementCommand request, CancellationToken cancellationToken)
    {
        var accountMovement = await _accountMovementQueryDataPort.GetAccountMovementAsync(request.AccountMovementId);
        AppRule.ExistsAndActive(accountMovement,
            new BusinessValidationException($"{string.Format(_stringLocalizer["NotFound"], _stringLocalizer["Wallet"])}", $"{_stringLocalizer["NotFound"]} AccountMovementId: {request.AccountMovementId}"));
        AppRule.True(accountMovement.Wallet.UserId == request.UserId,
            new BusinessValidationException($"{_stringLocalizer["NotFound"]}", $"{_stringLocalizer["NotFound"]} AccountMovementId: {request.AccountMovementId}"));
        AppRule.True(accountMovement.TransactionStatus != TransactionStatus.Successful,
            new BusinessValidationException($"{_stringLocalizer["NotFound"]}", $"{_stringLocalizer["NotFound"]} AccountMovementId: {request.AccountMovementId}"));

        accountMovement.MarkAsDeleted();

        var status = await _accountMovementCommandDataPort.SaveAsync(accountMovement);
        AppRule.True(status, new BusinessValidationException($"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["Wallet"])}", $"{string.Format(_stringLocalizer["NotUpdated"], _stringLocalizer["Wallet"])} UserId: {request.AccountMovementId}"));

        return new DeleteAccountMovementCommandResponse();
    }
}