using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetDaySaleStatistics;

public class GetDaySaleStatisticsQuery : IQuery<GetDaySaleStatisticsQueryResponse>
{

}
internal class GetDaySaleStatisticsQueryValidator : AbstractValidator<GetDaySaleStatisticsQuery>
{
    public GetDaySaleStatisticsQueryValidator()
    {
    }
}