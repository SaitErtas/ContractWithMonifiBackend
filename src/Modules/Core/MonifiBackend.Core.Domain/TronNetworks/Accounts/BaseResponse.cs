using System.Text.Json.Serialization;

namespace MonifiBackend.Core.Domain.TronNetworks.Accounts;

public class BaseResponse
{

    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("meta")]
    public Meta Meta { get; set; }

    [JsonPropertyName("error")]
    public string Error { get; set; }

    [JsonPropertyName("statusCode")]
    public int StatusCode { get; set; }
}
public class Meta
{
    [JsonPropertyName("at")]
    public long At { get; set; }

    [JsonPropertyName("page_size")]
    public int PageSize { get; set; }
}