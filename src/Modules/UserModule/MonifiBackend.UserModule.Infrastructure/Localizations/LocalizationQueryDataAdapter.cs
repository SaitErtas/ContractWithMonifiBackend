using Microsoft.EntityFrameworkCore;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.UserModule.Domain.Localizations;
using MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.UserModule.Infrastructure.Localizations;

public class LocalizationQueryDataAdapter : ILocalizationQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public LocalizationQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<Country> GetCountryAsync(int id)
    {
        var entity = await _dbContext.Countries
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id);
        return entity.Map();
    }
    public async Task<List<Country>> GetCountriesAsync()
    {
        return await _dbContext.Countries
            .Select(x => x.Map())
            .AsNoTracking()
            .ToListAsync();
    }

    public async Task<Language> GetLanguageAsync(int id)
    {
        var entity = await _dbContext.Languages
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id);
        return entity.Map();
    }

    public async Task<List<Language>> GetLanguagesAsync()
    {
        return await _dbContext.Languages
            .Select(x => x.Map())
            .AsNoTracking()
            .ToListAsync();
    }
}
