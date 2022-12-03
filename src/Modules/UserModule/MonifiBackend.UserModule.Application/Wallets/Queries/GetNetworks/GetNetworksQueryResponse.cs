using MonifiBackend.UserModule.Domain.Wallets;

namespace MonifiBackend.UserModule.Application.Wallets.Queries.GetNetworks;

public class GetNetworksQueryResponse
{
    public GetNetworksQueryResponse(List<Network> networks)
    {
        Networks = networks.Select(x => new GetNetwork(x)).ToList();
        Count = networks.Count;
    }
    public List<GetNetwork> Networks { get; private set; }
    public int Count { get; private set; }
}
public class GetNetwork
{
    public GetNetwork(Network network)
    {
        Id = network.Id;
        Name = network.Name;
        value = network.Name;
    }

    public int Id { get; private set; }
    public string Name { get; private set; }    
    public string value { get; private set; }
}