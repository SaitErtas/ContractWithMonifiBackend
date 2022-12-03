using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Commands.TransferAccept;

public class TransferAcceptCommand : ICommand<TransferAcceptCommandResponse>
{
    public TransferAcceptCommand(string email)
    {
        Email = email;
    }
    public string Email { get; set; }
}
internal class TransferAcceptCommandValidator : AbstractValidator<TransferAcceptCommand>
{
    public TransferAcceptCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Email))}");
    }
}