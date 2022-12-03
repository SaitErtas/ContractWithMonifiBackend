using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Wallets.Queries.GetNetworks;

public class GetNetworksQuery : IQuery<GetNetworksQueryResponse>
{
    public GetNetworksQuery()
    {
    }

}
internal class GetNetworksQueryValidator : AbstractValidator<GetNetworksQuery>
{
    public GetNetworksQueryValidator()
    {

    }
}