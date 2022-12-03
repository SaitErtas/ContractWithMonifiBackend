using MonifiBackend.Core.Domain.Accounts;
using MonifiBackend.Core.Domain.BscScans.Accounts;

namespace MonifiBackend.Core.Domain.BscScans;

public interface IBscScanAccountsDataPort
{
    /// <summary>
    /// Get BNB Balance for a Single Address
    /// </summary>
    /// <param name="request">BnbBalanceRequest Model</param>
    /// <returns>Returns the BNB balance of a given address.</returns>
    Task<BnbBalance?> GetBnbBalanceAsync(BnbBalanceRequest request);

    /// <summary>
    /// Get a list of 'Normal' Transactions By Address
    /// </summary>
    /// <param name="request">NormalTransactionRequest Model</param>
    /// <returns>Returns the list of transactions performed by an address, with optional pagination.</returns>
    /// <remarks>This API endpoint returns a maximum of 10000 records only.</remarks>
    Task<NormalTransactions?> GetNormalTransactionsByAddressAsync(NormalTransactionsRequest request);


    /// <summary>
    /// Get a list of 'Normal' Transactions By Address
    /// </summary>
    /// <param name="request">NormalTransactionRequest Model</param>
    /// <returns>Returns the list of transactions performed by an address, with optional pagination.</returns>
    /// <remarks>This API endpoint returns a maximum of 10000 records only.</remarks>
    Task<Bep20TokenTransferEvents?> GetBep20TokenTransferEventsByAddressAsync(Bep20TokenTransferEventsRequest request);
}
