using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetStatistic;

public class GetStatisticsQuery : IQuery<GetStatisticsQueryResponse>
{
    public GetStatisticsQuery(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; }
}

internal class GetStatisticsQueryValidator : AbstractValidator<GetStatisticsQuery>
{
    public GetStatisticsQueryValidator()
    {

    }
}