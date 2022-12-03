using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.TransferCheck;

public class TransferCheckQuery : IQuery<TransferCheckQueryResponse>
{
    public TransferCheckQuery(string email)
    {
        Email = email;
    }
    public string Email { get; }

}
internal class TransferCheckQueryValidator : AbstractValidator<TransferCheckQuery>
{
    public TransferCheckQueryValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email alanı boş bırakılamaz.");

    }
}