using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.BscScanAddress;

public class BscScanAddressQuery : IQuery<BscScanAddressQueryResponse>
{
    public BscScanAddressQuery(string address)
    {
        Address = address;
    }
    public string Address { get; }
}

internal class BscScanAddressQueryValidator : AbstractValidator<BscScanAddressQuery>
{
    public BscScanAddressQueryValidator()
    {
        RuleFor(x => x.Address)
            .NotEmpty().WithMessage("Id is not null.");
    }
}