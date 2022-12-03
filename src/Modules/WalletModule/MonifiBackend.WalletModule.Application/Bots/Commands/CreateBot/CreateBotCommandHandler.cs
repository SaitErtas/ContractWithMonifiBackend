using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.WalletModule.Domain.Bots;

namespace MonifiBackend.WalletModule.Application.Bots.Commands.CreateBot;

internal class CreateBotCommandHandler : ICommandHandler<CreateBotCommand, CreateBotCommandResponse>
{
    private readonly IBotCommandDataPort _settingCommandDataPort;
    public CreateBotCommandHandler(IBotCommandDataPort settingCommandDataPort)
    {
        _settingCommandDataPort = settingCommandDataPort;
    }
    public async Task<CreateBotCommandResponse> Handle(CreateBotCommand request, CancellationToken cancellationToken)
    {
        var bot = Bot.CreateNew(request.Hour, request.Minute, request.WorkingRange.ToEnum<WorkingRange>(), request.Range, request.Amount, request.PackageDetailId, BaseStatus.Active);
        var botId = await _settingCommandDataPort.CreateAsync(bot);
        AppRule.NotNegativeOrZero(botId, new BusinessValidationException(BusinessValidationMessageType.NOT_CREATED, nameof(request.Hour), request.Hour));

        return new CreateBotCommandResponse();
    }
}