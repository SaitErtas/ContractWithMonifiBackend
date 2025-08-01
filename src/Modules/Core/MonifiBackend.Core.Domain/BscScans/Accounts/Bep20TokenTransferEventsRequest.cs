﻿using System.Text.Json.Serialization;

namespace MonifiBackend.Core.Domain.BscScans.Accounts;

/// <summary>
/// Bep20Token Transfer Request Model
/// </summary>
public class Bep20TokenTransferEventsRequest
{
    /// <summary>
    /// the string representing the addresses to check for balance
    /// </summary>
    [JsonPropertyName("address")]
    public string? Address { get; set; }


    /// <summary>
    /// the integer block number to start searching for transactions (default is 0)
    /// </summary>
    [JsonPropertyName("startblock")]
    public int StartBlock { get; set; } = 0;

    /// <summary>
    /// the integer block number to stop searching for transactions (default is 99999999)
    /// </summary>
    [JsonPropertyName("endblock")]
    public int EndBlock { get; set; } = 99999999;

    /// <summary>
    /// the integer page number, if pagination is enabled (default is 1)
    /// </summary>
    [JsonPropertyName("page")]
    public int Page { get; set; } = 1;

    /// <summary>
    /// the number of transactions displayed per page (default is 10)
    /// </summary>
    [JsonPropertyName("offset")]
    public int OffSet { get; set; } = 100;

    /// <summary>
    /// the sorting preference, use asc to sort by ascending and desc to sort by descending (default is asc)
    /// </summary>
    [JsonIgnore]
    public Sort Sort { get; set; } = Sort.Desc;

    /// <summary>
    /// the sorting preference, use asc to sort by ascending and desc to sort by descending (default is asc)
    /// </summary>

    [JsonPropertyName("sort")]
    public string SortParam => Sort.ToString().ToLower();
}
