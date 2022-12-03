using System.Text.Json.Serialization;

namespace MonifiBackend.Core.Domain.Accounts;

/// <summary>
/// Bnb Balance
/// </summary>
public class BnbBalance : BaseResponse
{
    /// <summary>
    /// Result
    /// </summary>
    [JsonPropertyName("result")]
    public string? Result { get; set; }
}