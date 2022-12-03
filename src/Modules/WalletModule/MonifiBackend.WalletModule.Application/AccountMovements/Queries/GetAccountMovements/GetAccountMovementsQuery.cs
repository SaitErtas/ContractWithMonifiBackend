using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetAccountMovements;

public class GetAccountMovementsQuery : IQuery<GetAccountMovementsQueryResponse>
{
    public GetAccountMovementsQuery(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; }

}
internal class GetAccountMovementsQueryValidator : AbstractValidator<GetAccountMovementsQuery>
{
    public GetAccountMovementsQueryValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage("UserId alanı boş bırakılamaz.");

    }
}