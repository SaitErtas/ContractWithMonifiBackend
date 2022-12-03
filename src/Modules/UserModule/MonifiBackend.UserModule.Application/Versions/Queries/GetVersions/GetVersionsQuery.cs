using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Versions.Queries.GetVersions;

public class GetVersionsQuery : IQuery<GetVersionsQueryResponse>
{
    public GetVersionsQuery()
    {
    }

}
internal class GetVersionsQueryValidator : AbstractValidator<GetVersionsQuery>
{
    public GetVersionsQueryValidator()
    {

    }
}