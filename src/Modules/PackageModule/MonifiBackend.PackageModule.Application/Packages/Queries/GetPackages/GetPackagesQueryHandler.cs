using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.PackageModule.Domain.Packages;

namespace MonifiBackend.PackageModule.Application.Packages.Queries.GetPackages;

internal class GetPackagesQueryHandler : IQueryHandler<GetPackagesQuery, GetPackagesQueryResponse>
{
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    public GetPackagesQueryHandler(IPackageQueryDataPort packageQueryDataPort)
    {
        _packageQueryDataPort = packageQueryDataPort;
    }
    public async Task<GetPackagesQueryResponse> Handle(GetPackagesQuery request, CancellationToken cancellationToken)
    {
        var packages = await _packageQueryDataPort.GetsAsync();

        return new GetPackagesQueryResponse(packages);
    }
}
