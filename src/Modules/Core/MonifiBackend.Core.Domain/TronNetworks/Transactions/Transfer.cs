using System.Text.Json.Serialization;

namespace MonifiBackend.Core.Domain.TronNetworks.Transactions;

public class Transfer
{
    [JsonPropertyName("total")]
    public int Total { get; set; }


    [JsonPropertyName("rangeTotal")]
    public int RangeTotal { get; set; }

    [JsonPropertyName("token_transfers")]
    public List<TokenTransfer> TokenTransfers { get; set; }
}

public class FromAddressTagModel
{
    [JsonPropertyName("from_address_tag")]
    public string FromAddressTag { get; set; }

    [JsonPropertyName("from_address_tag_logo")]
    public string FromAddressTagLogo { get; set; }
}

public class ParameterModel
{
    [JsonPropertyName("_value")]
    public string Value { get; set; }

    [JsonPropertyName("_to")]
    public string To { get; set; }
}

public class ToAddressTagModel
{
    [JsonPropertyName("to_address_tag_logo")]
    public string ToAddressTagLogo { get; set; }

    [JsonPropertyName("to_address_tag")]
    public string ToAddressTag { get; set; }
}

public class TokenInfoModel
{
    [JsonPropertyName("tokenId")]
    public string TokenId { get; set; }

    [JsonPropertyName("tokenAbbr")]
    public string TokenAbbr { get; set; }

    [JsonPropertyName("tokenName")]
    public string TokenName { get; set; }

    [JsonPropertyName("tokenDecimal")]
    public int TokenDecimal { get; set; }

    [JsonPropertyName("tokenCanShow")]
    public int TokenCanShow { get; set; }

    [JsonPropertyName("tokenType")]
    public string TokenType { get; set; }

    [JsonPropertyName("tokenLogo")]
    public string TokenLogo { get; set; }

    [JsonPropertyName("tokenLevel")]
    public string TokenLevel { get; set; }

    [JsonPropertyName("vip")]
    public bool Vip { get; set; }
}

public class TokenTransfer
{
    [JsonPropertyName("transaction_id")]
    public string TransactionId { get; set; }

    [JsonPropertyName("block_ts")]
    public long BlockTs { get; set; }

    [JsonPropertyName("from_address")]
    public string FromAddress { get; set; }

    [JsonPropertyName("from_address_tag")]
    public FromAddressTagModel FromAddressTag { get; set; }

    [JsonPropertyName("to_address")]
    public string ToAddress { get; set; }

    [JsonPropertyName("to_address_tag")]
    public ToAddressTagModel ToAddressTag { get; set; }

    [JsonPropertyName("block")]
    public int Block { get; set; }

    [JsonPropertyName("contract_address")]
    public string ContractAddress { get; set; }

    [JsonPropertyName("trigger_info")]
    public TriggerInfo TriggerInfo { get; set; }

    [JsonPropertyName("quant")]
    public string Quant { get; set; }

    [JsonPropertyName("approval_amount")]
    public string ApprovalAmount { get; set; }

    [JsonPropertyName("event_type")]
    public string EventType { get; set; }

    [JsonPropertyName("contract_type")]
    public string ContractType { get; set; }

    [JsonPropertyName("confirmed")]
    public bool Confirmed { get; set; }

    [JsonPropertyName("contractRet")]
    public string ContractRet { get; set; }

    [JsonPropertyName("finalResult")]
    public string FinalResult { get; set; }

    [JsonPropertyName("tokenInfo")]
    public TokenInfo TokenInfo { get; set; }

    [JsonPropertyName("fromAddressIsContract")]
    public bool FromAddressIsContract { get; set; }

    [JsonPropertyName("toAddressIsContract")]
    public bool ToAddressIsContract { get; set; }

    [JsonPropertyName("revert")]
    public bool Revert { get; set; }
}

public class TriggerInfoModel
{
    [JsonPropertyName("method")]
    public string Method { get; set; }

    [JsonPropertyName("data")]
    public string Data { get; set; }

    [JsonPropertyName("parameter")]
    public Parameter Parameter { get; set; }

    [JsonPropertyName("methodName")]
    public string MethodName { get; set; }

    [JsonPropertyName("contract_address")]
    public string ContractAddress { get; set; }

    [JsonPropertyName("call_value")]
    public int CallValue { get; set; }
}

