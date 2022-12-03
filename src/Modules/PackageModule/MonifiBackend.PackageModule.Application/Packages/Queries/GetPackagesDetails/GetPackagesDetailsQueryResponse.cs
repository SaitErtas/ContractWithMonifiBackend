using MonifiBackend.PackageModule.Domain.ReadModel;

namespace MonifiBackend.PackageModule.Application.Packages.Queries.GetPackagesDetails;

public class GetPackagesDetailsQueryResponse
{
    public GetPackagesDetailsQueryResponse(List<PackageDetailReadModel> packageDetails)
    {
        PackageDetails = packageDetails;
    }

    public List<PackageDetailReadModel> PackageDetails { get; set; }
}
