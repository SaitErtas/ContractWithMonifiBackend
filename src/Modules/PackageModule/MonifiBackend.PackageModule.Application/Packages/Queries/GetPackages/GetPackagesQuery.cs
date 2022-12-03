using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.PackageModule.Application.Packages.Queries.GetPackages;


public class GetPackagesQuery : IQuery<GetPackagesQueryResponse>
{
    public GetPackagesQuery()
    {
    }

}
internal class GetPackagesQueryValidator : AbstractValidator<GetPackagesQuery>
{
    public GetPackagesQueryValidator()
    {

    }
}