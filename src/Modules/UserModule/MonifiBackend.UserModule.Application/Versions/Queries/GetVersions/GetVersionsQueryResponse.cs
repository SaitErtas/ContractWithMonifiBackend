namespace MonifiBackend.UserModule.Application.Versions.Queries.GetVersions;

public class GetVersionsQueryResponse
{
    public GetVersionsQueryResponse(List<Domain.Versions.Version> versions)
    {
        Versions = versions.Select(s => new GetVersionResponse(s)).ToList();
    }

    public List<GetVersionResponse> Versions { get; private set; }
}
public class GetVersionResponse
{
    public GetVersionResponse(Domain.Versions.Version version)
    {
        Name = version.Name;
        CreatedAt = version.CreatedAt;
        VersionDetail = version.Details.Select(s => new GetVersionDetailResponse(s)).ToList();
    }
    public string Name { get; private set; }
    public DateTime CreatedAt { get; private set; }
    public List<GetVersionDetailResponse> VersionDetail { get; private set; }
}
public class GetVersionDetailResponse
{
    public GetVersionDetailResponse(Domain.Versions.VersionDetail versionDetail)
    {
        Name = versionDetail.Name;
    }
    public string Name { get; private set; }
}