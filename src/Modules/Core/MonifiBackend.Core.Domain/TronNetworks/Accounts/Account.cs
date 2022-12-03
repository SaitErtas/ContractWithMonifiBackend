using System.Text.Json.Serialization;

namespace MonifiBackend.Core.Domain.TronNetworks.Accounts;

public class Account : BaseResponse
{
    [JsonPropertyName("data")]
    public List<object> Data { get; set; }
}
