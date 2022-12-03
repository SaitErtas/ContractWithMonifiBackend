using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.PackageModule.Domain.Packages;

namespace MonifiBackend.PackageModule.Application.Packages.Queries.GetPackagesDetails;

internal class GetPackagesDetailsQueryHandler : IQueryHandler<GetPackagesDetailsQuery, GetPackagesDetailsQueryResponse>
{
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    public GetPackagesDetailsQueryHandler(IPackageQueryDataPort packageQueryDataPort)
    {
        _packageQueryDataPort = packageQueryDataPort;
    }
    public async Task<GetPackagesDetailsQueryResponse> Handle(GetPackagesDetailsQuery request, CancellationToken cancellationToken)
    {
        var packages = await _packageQueryDataPort.GetPackageDetailAsync();

        return new GetPackagesDetailsQueryResponse(packages);
    }
}