using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Commands.DeleteAccountMovement;

public class DeleteAccountMovementCommand : ICommand<DeleteAccountMovementCommandResponse>
{
    public DeleteAccountMovementCommand(int userId, int accountMovementId)
    {
        UserId = userId;
        AccountMovementId = accountMovementId;
    }

    [JsonIgnore]
    public int UserId { get; set; }
    public int AccountMovementId { get; set; }
}
internal class DeleteAccountMovementCommandValidator : AbstractValidator<DeleteAccountMovementCommand>
{
    public DeleteAccountMovementCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
        RuleFor(x => x.AccountMovementId)
            .GreaterThan(0)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.AccountMovementId))}");
    }
}