using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.ApyAnalysis;

public class ApyAnalysisQuery : IQuery<ApyAnalysisQueryResponse>
{

    public ApyAnalysisQuery(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; }
}
internal class ApyAnalysisQueryValidator : AbstractValidator<ApyAnalysisQuery>
{
    public ApyAnalysisQueryValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
    }
}