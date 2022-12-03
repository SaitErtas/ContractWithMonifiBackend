using MonifiBackend.Core.Domain.TronNetworks.Accounts;
using MonifiBackend.Core.Domain.TronNetworks.Transactions;

namespace MonifiBackend.Core.Domain.TronNetworks;

public interface ITronNetworkAccountsDataPort
{
    Task<Account> GetAccountsAsync(string address);
    public Task<Transfer> GetTransfersAsync(string address);
}
