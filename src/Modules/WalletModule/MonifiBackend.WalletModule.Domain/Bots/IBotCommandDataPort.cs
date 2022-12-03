using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Domain.Bots;

public interface IBotCommandDataPort : ICommandDataPort
{
    Task<int> CreateAsync(Bot bot);
    Task<bool> SaveAsync(Bot bot);
}