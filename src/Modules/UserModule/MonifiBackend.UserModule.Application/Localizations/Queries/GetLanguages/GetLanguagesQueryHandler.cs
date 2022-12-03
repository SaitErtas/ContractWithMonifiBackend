using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.UserModule.Domain.Localizations;

namespace MonifiBackend.UserModule.Application.Localizations.Queries.GetLanguages;

internal class GetLanguagesQueryHandler : IQueryHandler<GetLanguagesQuery, GetLanguagesQueryResponse>
{
    private readonly ILocalizationQueryDataPort _localizationQueryDataPort;
    public GetLanguagesQueryHandler(ILocalizationQueryDataPort localizationQueryDataPort)
    {
        _localizationQueryDataPort = localizationQueryDataPort;
    }
    public async Task<GetLanguagesQueryResponse> Handle(GetLanguagesQuery request, CancellationToken cancellationToken)
    {
        var languages = await _localizationQueryDataPort.GetLanguagesAsync();

        return new GetLanguagesQueryResponse(languages);
    }
}