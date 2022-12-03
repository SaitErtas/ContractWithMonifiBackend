using Microsoft.EntityFrameworkCore;
using MonifiBackend.Data.Infrastructure.Contexts;
using MonifiBackend.UserModule.Domain.Versions;
using MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;

namespace MonifiBackend.UserModule.Infrastructure.Versions;

public class VersionQueryDataAdapter : IVersionQueryDataPort
{
    private readonly IMonifiBackendDbContext _dbContext;
    public VersionQueryDataAdapter(IMonifiBackendDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<List<Domain.Versions.Version>> GetAsync()
    {
        return await _dbContext.Versions
            .Include(i => i.VersionDetails)
            .OrderByDescending(o => o.CreatedAt)
            .Select(s => s.Map())
            .ToListAsync();
    }
}