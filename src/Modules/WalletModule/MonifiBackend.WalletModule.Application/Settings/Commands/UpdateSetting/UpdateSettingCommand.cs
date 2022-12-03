using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Settings.Commands.UpdateSetting;

public class UpdateSettingCommand : ICommand<UpdateSettingCommandResponse>
{
    public decimal MonifiPrice { get; set; }
    public string BscScanAddress { get; set; }
    public string TronNetworkAddress { get; set; }
    public string BscScanTokenSymbol { get; set; }
    public string TronNetworkTokenSymbol { get; set; }
    public bool MaintenanceMode { get; set; }
}
internal class UpdateSettingCommandValidator : AbstractValidator<UpdateSettingCommand>
{
    public UpdateSettingCommandValidator()
    {
    }
}