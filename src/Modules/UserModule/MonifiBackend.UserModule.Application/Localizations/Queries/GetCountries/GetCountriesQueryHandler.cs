using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.UserModule.Domain.Localizations;

namespace MonifiBackend.UserModule.Application.Localizations.Queries.GetCountries;

internal class GetCountriesQueryHandler : IQueryHandler<GetCountriesQuery, GetCountriesQueryResponse>
{
    private readonly ILocalizationQueryDataPort _localizationQueryDataPort;
    public GetCountriesQueryHandler(ILocalizationQueryDataPort localizationQueryDataPort)
    {
        _localizationQueryDataPort = localizationQueryDataPort;
    }
    public async Task<GetCountriesQueryResponse> Handle(GetCountriesQuery request, CancellationToken cancellationToken)
    {
        var countries = await _localizationQueryDataPort.GetCountriesAsync();

        return new GetCountriesQueryResponse(countries);
    }
}