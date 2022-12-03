using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.WalletModule.Domain.Bots;

namespace MonifiBackend.WalletModule.Application.Bots.Queries.GetBots;

internal class GetBotsQueryHandler : IQueryHandler<GetBotsQuery, GetBotsQueryResponse>
{
    private readonly IBotQueryDataPort _settingQueryDataPort;
    public GetBotsQueryHandler(IBotQueryDataPort settingQueryDataPort)
    {
        _settingQueryDataPort = settingQueryDataPort;
    }
    public async Task<GetBotsQueryResponse> Handle(GetBotsQuery request, CancellationToken cancellationToken)
    {
        var bots = await _settingQueryDataPort.GetAsync();

        return new GetBotsQueryResponse(bots);
    }
}