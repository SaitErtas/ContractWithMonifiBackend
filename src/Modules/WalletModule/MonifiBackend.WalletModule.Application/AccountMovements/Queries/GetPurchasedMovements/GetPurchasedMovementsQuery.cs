using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetPurchasedMovements;

public class GetPurchasedMovementsQuery : IQuery<GetPurchasedMovementsQueryResponse>
{
    public GetPurchasedMovementsQuery(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; }

}
internal class GetPurchasedMovementsQueryValidator : AbstractValidator<GetPurchasedMovementsQuery>
{
    public GetPurchasedMovementsQueryValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage("UserId alanı boş bırakılamaz.");

    }
}