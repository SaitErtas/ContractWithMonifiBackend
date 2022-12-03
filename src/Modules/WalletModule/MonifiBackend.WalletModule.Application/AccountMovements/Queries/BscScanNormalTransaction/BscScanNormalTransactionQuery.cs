using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.BscScanNormalTransaction;

public class BscScanNormalTransactionQuery : IQuery<BscScanNormalTransactionQueryResponse>
{
    public BscScanNormalTransactionQuery(string address)
    {
        Address = address;
    }
    public string Address { get; }
}

internal class BscScanNormalTransactionQueryValidator : AbstractValidator<BscScanNormalTransactionQuery>
{
    public BscScanNormalTransactionQueryValidator()
    {
        RuleFor(x => x.Address)
            .NotEmpty().WithMessage("Id is not null.");
    }
}