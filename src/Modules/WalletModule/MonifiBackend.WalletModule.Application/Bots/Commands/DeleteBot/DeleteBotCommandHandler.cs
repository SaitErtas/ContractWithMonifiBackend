using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.WalletModule.Domain.Bots;

namespace MonifiBackend.WalletModule.Application.Bots.Commands.DeleteBot;

internal class DeleteBotCommandHandler : ICommandHandler<DeleteBotCommand, DeleteBotCommandResponse>
{
    private readonly IBotQueryDataPort _settingQueryDataPort;
    private readonly IBotCommandDataPort _settingCommandDataPort;
    public DeleteBotCommandHandler(IBotCommandDataPort settingCommandDataPort, IBotQueryDataPort settingQueryDataPort)
    {
        _settingCommandDataPort = settingCommandDataPort;
        _settingQueryDataPort = settingQueryDataPort;
    }
    public async Task<DeleteBotCommandResponse> Handle(DeleteBotCommand request, CancellationToken cancellationToken)
    {
        var bot = await _settingQueryDataPort.GetAsync(request.Id);
        bot.MarkAsDeleted();
        await _settingCommandDataPort.SaveAsync(bot);

        return new DeleteBotCommandResponse();
    }
}