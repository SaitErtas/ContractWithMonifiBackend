using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetAdminStatistics;

public class GetAdminStatisticsQuery : IQuery<GetAdminStatisticsQueryResponse>
{
    public GetAdminStatisticsQuery()
    {
    }
}

internal class GetAdminStatisticsQueryValidator : AbstractValidator<GetAdminStatisticsQuery>
{
    public GetAdminStatisticsQueryValidator()
    {

    }
}