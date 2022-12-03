using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.UserModule.Domain.Wallets;

namespace MonifiBackend.UserModule.Application.Wallets.Queries.GetNetworks;

internal class GetNetworksQueryHandler : IQueryHandler<GetNetworksQuery, GetNetworksQueryResponse>
{
    private readonly IWalletQueryDataPort _walletQueryDataPort;
    public GetNetworksQueryHandler(IWalletQueryDataPort walletQueryDataPort)
    {
        _walletQueryDataPort = walletQueryDataPort;
    }
    public async Task<GetNetworksQueryResponse> Handle(GetNetworksQuery request, CancellationToken cancellationToken)
    {
        var networks = await _walletQueryDataPort.GetNetworksAsync();

        return new GetNetworksQueryResponse(networks);
    }
}