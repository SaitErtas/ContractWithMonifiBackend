using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.EarningsPages;

public class EarningsPagesQuery : IQuery<EarningsPagesQueryResponse>
{
    public EarningsPagesQuery(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; }
}
internal class EarningsPagesQueryValidator : AbstractValidator<EarningsPagesQuery>
{
    public EarningsPagesQueryValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
    }
}