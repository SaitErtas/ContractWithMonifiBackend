using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.GetAccountActivities;

public class GetAccountActivitiesQuery : IQuery<GetAccountActivitiesQueryResponse>
{
    public GetAccountActivitiesQuery()
    {
    }
}

internal class GetAccountActivitiesQueryValidator : AbstractValidator<GetAccountActivitiesQuery>
{
    public GetAccountActivitiesQueryValidator()
    {

    }
}