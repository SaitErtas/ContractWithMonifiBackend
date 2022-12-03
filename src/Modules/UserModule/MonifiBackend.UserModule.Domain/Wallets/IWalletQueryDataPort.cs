using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Domain.Wallets;

public interface IWalletQueryDataPort : IQueryDataPort
{
    Task<List<Network>> GetNetworksAsync();
    Task<Network> GetNetworkAsync(int id);
}
