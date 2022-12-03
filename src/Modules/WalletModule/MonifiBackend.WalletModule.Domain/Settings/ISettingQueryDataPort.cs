using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Domain.Settings;

public interface ISettingQueryDataPort : IQueryDataPort
{
    Task<Setting> GetAsync(int id);
}
