using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Domain.Settings;

public interface ISettingCommandDataPort : ICommandDataPort
{
    Task<bool> SaveAsync(Setting setting);
}
