using System.Text.Json.Serialization;

namespace MonifiBackend.Core.Domain.TronNetworks.Transactions;

public class Transaction
{
    [JsonPropertyName("total")]
    public int Total { get; set; }

    [JsonPropertyName("rangeTotal")]
    public int RangeTotal { get; set; }

    [JsonPropertyName("data")]
    public List<Datum> Data { get; set; }

    [JsonPropertyName("wholeChainTxCount")]
    public long WholeChainTxCount { get; set; }

    [JsonPropertyName("contractMap")]
    public ContractMap ContractMap { get; set; }

    [JsonPropertyName("contractInfo")]
    public ContractInfo ContractInfo { get; set; }
}
public class ContractData
{
    [JsonPropertyName("amount")]
    public int Amount { get; set; }

    [JsonPropertyName("owner_address")]
    public string OwnerAddress { get; set; }

    [JsonPropertyName("to_address")]
    public string ToAddress { get; set; }

    [JsonPropertyName("data")]
    public string Data { get; set; }

    [JsonPropertyName("contract_address")]
    public string ContractAddress { get; set; }
}

public class ContractInfo
{
    [JsonPropertyName("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")]
    public TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t { get; set; }
}

public class ContractMap
{
    [JsonPropertyName("TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G")]
    public bool TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G { get; set; }

    [JsonPropertyName("TCZ6hAWZD7iPceqA7gmyVoPV5f9Lw2ujVk")]
    public bool TCZ6hAWZD7iPceqA7gmyVoPV5f9Lw2ujVk { get; set; }

    [JsonPropertyName("TPAR96FRrfr4SYvdZ5qpKknr3S7GSg3ksM")]
    public bool TPAR96FRrfr4SYvdZ5qpKknr3S7GSg3ksM { get; set; }

    [JsonPropertyName("TUntyv4ndZaZXBcpxwDTFgzEtciSrMq2kX")]
    public bool TUntyv4ndZaZXBcpxwDTFgzEtciSrMq2kX { get; set; }

    [JsonPropertyName("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")]
    public bool TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t { get; set; }

    [JsonPropertyName("TYASr5UV6HEcXatwdFQfmLVUqQQQMUxHLS")]
    public bool TYASr5UV6HEcXatwdFQfmLVUqQQQMUxHLS { get; set; }

    [JsonPropertyName("TP4f1HibcXKp2fjzcip35twHA5MAvivzgd")]
    public bool TP4f1HibcXKp2fjzcip35twHA5MAvivzgd { get; set; }

    [JsonPropertyName("TUHBKmbrX2Xs8GvTHsYoNCczmZ3QLbd22y")]
    public bool TUHBKmbrX2Xs8GvTHsYoNCczmZ3QLbd22y { get; set; }

    [JsonPropertyName("TTkPhAy9WbpRCVBzS4KYFsRGiKL61ygLVG")]
    public bool TTkPhAy9WbpRCVBzS4KYFsRGiKL61ygLVG { get; set; }

    [JsonPropertyName("TPt3z2eLzvGFDFthdBd2bvq42nhtHtaXUP")]
    public bool TPt3z2eLzvGFDFthdBd2bvq42nhtHtaXUP { get; set; }
}

public class Cost
{
    [JsonPropertyName("net_fee")]
    public int NetFee { get; set; }

    [JsonPropertyName("energy_usage")]
    public int EnergyUsage { get; set; }

    [JsonPropertyName("fee")]
    public int Fee { get; set; }

    [JsonPropertyName("energy_fee")]
    public int EnergyFee { get; set; }

    [JsonPropertyName("energy_usage_total")]
    public int EnergyUsageTotal { get; set; }

    [JsonPropertyName("origin_energy_usage")]
    public int OriginEnergyUsage { get; set; }

    [JsonPropertyName("net_usage")]
    public int NetUsage { get; set; }
}

public class Datum
{
    [JsonPropertyName("block")]
    public int Block { get; set; }

    [JsonPropertyName("hash")]
    public string Hash { get; set; }

    [JsonPropertyName("timestamp")]
    public object Timestamp { get; set; }

    [JsonPropertyName("ownerAddress")]
    public string OwnerAddress { get; set; }

    [JsonPropertyName("toAddressList")]
    public List<string> ToAddressList { get; set; }

    [JsonPropertyName("toAddress")]
    public string ToAddress { get; set; }

    [JsonPropertyName("contractType")]
    public int ContractType { get; set; }

    [JsonPropertyName("confirmed")]
    public bool Confirmed { get; set; }

    [JsonPropertyName("revert")]
    public bool Revert { get; set; }

    [JsonPropertyName("contractData")]
    public ContractData ContractData { get; set; }

    [JsonPropertyName("SmartCalls")]
    public string SmartCalls { get; set; }

    [JsonPropertyName("Events")]
    public string Events { get; set; }

    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("data")]
    public string Data { get; set; }

    [JsonPropertyName("fee")]
    public string Fee { get; set; }

    [JsonPropertyName("contractRet")]
    public string ContractRet { get; set; }

    [JsonPropertyName("result")]
    public string Result { get; set; }

    [JsonPropertyName("amount")]
    public string Amount { get; set; }

    [JsonPropertyName("cost")]
    public Cost Cost { get; set; }

    [JsonPropertyName("tokenInfo")]
    public TokenInfo TokenInfo { get; set; }

    [JsonPropertyName("tokenType")]
    public string TokenType { get; set; }

    [JsonPropertyName("trigger_info")]
    public TriggerInfo TriggerInfo { get; set; }

    [JsonPropertyName("ownerAddressTag")]
    public string OwnerAddressTag { get; set; }
}

public class Parameter
{
    [JsonPropertyName("_value")]
    public string Value { get; set; }

    [JsonPropertyName("_to")]
    public string To { get; set; }
}


public class TokenInfo
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

public class TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
{
    [JsonPropertyName("tag1")]
    public string Tag1 { get; set; }

    [JsonPropertyName("tag1Url")]
    public string Tag1Url { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("vip")]
    public bool Vip { get; set; }
}

public class TriggerInfo
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

