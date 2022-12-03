using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Domain.Localizations;

public interface ILocalizationQueryDataPort : IQueryDataPort
{
    Task<List<Country>> GetCountriesAsync();
    Task<Country> GetCountryAsync(int id);
    Task<List<Language>> GetLanguagesAsync();
    Task<Language> GetLanguageAsync(int id);
}
