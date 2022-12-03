using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetNoBonusPurchasedMovements;

public class GetNoBonusPurchasedMovementsQuery : IQuery<GetNoBonusPurchasedMovementsQueryResponse>
{
    public GetNoBonusPurchasedMovementsQuery(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; }

}
internal class GetNoBonusPurchasedMovementsQueryValidator : AbstractValidator<GetNoBonusPurchasedMovementsQuery>
{
    public GetNoBonusPurchasedMovementsQueryValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage("UserId alanı boş bırakılamaz.");

    }
}