using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.UserModule.Domain.Versions;

namespace MonifiBackend.UserModule.Application.Versions.Queries.GetVersions;

internal class GetVersionsQueryHandler : IQueryHandler<GetVersionsQuery, GetVersionsQueryResponse>
{
    private readonly IVersionQueryDataPort _versionQueryDataPort;
    public GetVersionsQueryHandler(IVersionQueryDataPort versionQueryDataPort)
    {
        _versionQueryDataPort = versionQueryDataPort;
    }
    public async Task<GetVersionsQueryResponse> Handle(GetVersionsQuery request, CancellationToken cancellationToken)
    {
        var versions = await _versionQueryDataPort.GetAsync();

        return new GetVersionsQueryResponse(versions);
    }
}