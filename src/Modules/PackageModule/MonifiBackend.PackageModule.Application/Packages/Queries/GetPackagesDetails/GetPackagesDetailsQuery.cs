using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.PackageModule.Application.Packages.Queries.GetPackagesDetails;

public class GetPackagesDetailsQuery : IQuery<GetPackagesDetailsQueryResponse>
{
    public GetPackagesDetailsQuery()
    {
    }

}
internal class GetPackagesDetailsQueryValidator : AbstractValidator<GetPackagesDetailsQuery>
{
    public GetPackagesDetailsQueryValidator()
    {

    }
}