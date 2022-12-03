using MonifiBackend.WalletModule.Domain.ReadModels;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Queries.TransferCheck;

public class TransferCheckQueryResponse
{
    public TransferCheckQueryResponse(List<NetworkTransfer> networkTransfer)
    {
        NetworkTransfers = networkTransfer;
    }
    public List<NetworkTransfer> NetworkTransfers { get; private set; }
}
