﻿using System.Text.Json.Serialization;

namespace MonifiBackend.Core.Domain.Accounts;

/// <summary>
/// 
/// </summary>
public class BaseResponse
{
    /// <summary>
    /// Status
    /// </summary>
    [JsonPropertyName("status")]
    public string Status { get; set; }

    /// <summary>
    /// Message
    /// </summary>
    [JsonPropertyName("message")]
    public string Message { get; set; }
}