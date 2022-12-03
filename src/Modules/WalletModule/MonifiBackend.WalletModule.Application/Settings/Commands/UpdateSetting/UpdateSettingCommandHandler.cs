using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.WalletModule.Domain.Settings;

namespace MonifiBackend.WalletModule.Application.Settings.Commands.UpdateSetting;

internal class UpdateSettingCommandHandler : ICommandHandler<UpdateSettingCommand, UpdateSettingCommandResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    private readonly ISettingCommandDataPort _settingCommandDataPort;
    public UpdateSettingCommandHandler(ISettingQueryDataPort settingQueryDataPort, ISettingCommandDataPort settingCommandDataPort)
    {
        _settingQueryDataPort = settingQueryDataPort;
        _settingCommandDataPort = settingCommandDataPort;
    }
    public async Task<UpdateSettingCommandResponse> Handle(UpdateSettingCommand request, CancellationToken cancellationToken)
    {
        var setting = await _settingQueryDataPort.GetAsync(DEFAULT_SETTING_VALUE);
        setting.SetMonifiPrice(request.MonifiPrice);
        setting.SetBscScanAddress(request.BscScanAddress);
        setting.SetTronNetworkAddress(request.TronNetworkAddress);
        setting.SetBscScanTokenSymbol(request.BscScanTokenSymbol);
        setting.SetTronNetworkTokenSymbol(request.TronNetworkTokenSymbol);

        await _settingCommandDataPort.SaveAsync(setting);

        return new UpdateSettingCommandResponse();
    }
}