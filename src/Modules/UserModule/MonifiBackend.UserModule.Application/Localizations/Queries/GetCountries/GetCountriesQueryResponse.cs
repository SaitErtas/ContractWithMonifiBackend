using MonifiBackend.UserModule.Domain.Localizations;

namespace MonifiBackend.UserModule.Application.Localizations.Queries.GetCountries;

public class GetCountriesQueryResponse
{
    public GetCountriesQueryResponse(List<Country> countries)
    {
        Countries = countries.Select(x => new GetCountry(x)).ToList();
        Count = countries.Count;
    }
    public List<GetCountry> Countries { get; private set; }
    public int Count { get; private set; }
}
public class GetCountry
{
    public GetCountry(Country country)
    {
        Id = country.Id;
        Name = country.Name;
        Flag = country.Flag;
        Iso2 = country.Iso2;
        Iso3 = country.Iso3;
    }

    public int Id { get; private set; }
    public string Name { get; private set; }
    public string Flag { get; private set; }
    public string Iso2 { get; private set; }
    public string Iso3 { get; private set; }
}