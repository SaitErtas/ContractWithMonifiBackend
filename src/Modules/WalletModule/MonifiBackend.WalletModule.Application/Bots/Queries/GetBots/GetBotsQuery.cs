using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Bots.Queries.GetBots;

public class GetBotsQuery : IQuery<GetBotsQueryResponse>
{

}
internal class GetSystemStatusQueryValidator : AbstractValidator<GetBotsQuery>
{
    public GetSystemStatusQueryValidator()
    {
    }
}
