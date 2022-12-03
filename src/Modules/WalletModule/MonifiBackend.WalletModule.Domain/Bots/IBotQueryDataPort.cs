using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Domain.Bots;

public interface IBotQueryDataPort : IQueryDataPort
{
    Task<List<Bot>> GetAsync();
    Task<Bot> GetAsync(int id);
    Task<List<Bot>> GetActiveAsync();
}