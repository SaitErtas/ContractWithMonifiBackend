using Microsoft.Extensions.Configuration;
using MonifiBackend.Core.Domain.TronNetworks;
using MonifiBackend.Core.Domain.TronNetworks.Accounts;
using MonifiBackend.Core.Domain.TronNetworks.Transactions;
using MonifiBackend.Core.Infrastructure.TronNetworks.Constants;
using System.Text.Json;

namespace MonifiBackend.Core.Infrastructure.TronNetworks;

public class TronNetworkAccountsDataAdapter : ITronNetworkAccountsDataPort
{
    private readonly HttpClient _bscScanHttpClient;
    private readonly IConfiguration _configuration;

    /// <inheritdoc />
    public TronNetworkAccountsDataAdapter(HttpClient bscScanHttpClient, IConfiguration configuration)
    {
        _configuration = configuration;
        _bscScanHttpClient = bscScanHttpClient;
    }
    public async Task<Account> GetAccountsAsync(string address)
    {
        var queryParameters = $"{_configuration["ApplicationSettings:TronNetworkOptions:Uri"]}{TronModule.ACCOUNT.Replace("{address}", address)}";
        using var response = await _bscScanHttpClient.GetAsync($"{queryParameters}")
            .ConfigureAwait(false);

        await using var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<Account>(responseStream);
        return result;
    }
    public async Task<Transfer> GetTransfersAsync(string address)
    {
        var queryParameters = $"{_configuration["ApplicationSettings:TronNetworkOptions:TronScanApi"]}{TronModule.TRANSFER.Replace("{address}", address)}";
        using var response = await _bscScanHttpClient.GetAsync($"{queryParameters}")
            .ConfigureAwait(false);

        await using var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<Transfer>(responseStream);
        return result;
    }

}
