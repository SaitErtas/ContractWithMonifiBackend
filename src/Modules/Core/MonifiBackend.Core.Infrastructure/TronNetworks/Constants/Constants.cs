﻿namespace MonifiBackend.Core.Infrastructure.TronNetworks.Constants;

/// <summary>
/// Tron Modules
/// </summary>
internal static class TronModule
{
    public const string ACCOUNT = "/accounts/{address}";
    public const string TRANSACTION = "/transaction?sort=-timestamp&count=true&limit=20&start=0&address={address}";
    public const string TRANSFER = "/token_trc20/transfers?limit=100&start=0&sort=-timestamp&count=true&relatedAddress={address}";
}

/// <summary>
/// Tron Accounts Module Actions
/// </summary>
internal static class AccountsModuleAction
{
    public const string ACCOUNT = "";
    public const string BALANCE_HISTORY = "balancehistory";
    public const string BALANCE_MULTI = "balancemulti";
    public const string TRANSACTION_LIST = "txlist";
    public const string TRANSACTION_LIST_INTERNAL = "txlistinternal";
    public const string TOKEN_TX = "tokentx";
    public const string TOKEN_NFT_TX = "tokennfttx";
    public const string GET_MINED_BLOCKS = "getminedblocks";
}

/// <summary>
/// BscScan Contracts Module Actions
/// </summary>
internal static class ContractsModuleAction
{
    public const string GET_ABI = "getabi";
    public const string GET_SOURCE_CODE = "getsourcecode";
}

/// <summary>
/// BscScan Contracts Module Actions
/// </summary>
internal static class TransactionsModuleAction
{
    public const string GET_TX_RECEIPT_STATUS = "gettxreceiptstatus";
}

/// <summary>
/// BscScan Blocks Module Actions
/// </summary>
internal static class BlocksModuleAction
{
    public const string GET_BLOCK_REWARD = "getblockreward";
    public const string GET_BLOCK_COUNT_DOWN = "getblockcountdown";
    public const string GET_BLOCK_NUMBER_BY_TIMESTAMP = "getblocknobytime";
    public const string GET_DAILY_AVG_BLOCK_SIZE = "dailyavgblocksize";
    public const string GET_DAILY_BLOCK_COUNT = "dailyblkcount";
    public const string GET_DAILY_BLOCK_REWARDS = "dailyblockrewards";
    public const string GET_DAILY_AVG_BLOCK_TIME = "dailyavgblocktime";
}

/// <summary>
/// BscScan Proxy Module Actions
/// </summary>
internal static class ProxyModuleAction
{
    public const string ETH_BLOCK_NUMBER = "eth_blockNumber";
    public const string ETH_GET_BLOCk_BY_NUMBER = "eth_getBlockByNumber";
    public const string ETH_GET_BLOCk_TRANSACTION_COUNT_BY_NUMBER = "eth_getBlockTransactionCountByNumber";
    public const string ETH_GET_TRANSACTION_BY_HASH = "eth_getTransactionByHash";
    public const string ETH_GET_TRANSACTION_BY_BLOCK_NUMBER_AND_INDEX = "eth_getTransactionByBlockNumberAndIndex";
    public const string ETH_GET_TRANSACTION_COUNT = "eth_getTransactionCount";
    public const string ETH_SEND_RAW_TRANSACTION = "eth_sendRawTransaction";
    public const string ETH_GET_TRANSACTION_RECEIPT = "eth_getTransactionReceipt";
    public const string ETH_CALL = "eth_call";
    public const string ETH_GET_CODE = "eth_getCode";
    public const string ETH_GET_STORAGE_AT = "eth_getStorageAt";
    public const string ETH_GAS_PRICE = "eth_gasPrice";
    public const string ETH_ESTIMATE_GAS = "eth_estimateGas";
}

/// <summary>
/// BscScan Token Module Actions
/// </summary>
internal static class TokenModuleAction
{
    public const string TOKEN_SUPPLY = "tokensupply";
    public const string TOKEN_C_SUPPLY = "tokenCsupply";
    public const string TOKEN_BALANCE = "tokenbalance";
    public const string TOKEN_HOLDER_LIST = "tokenholderlist";
    public const string TOKEN_SUPPLY_HISTORY = "tokensupplyhistory";
    public const string TOKEN_BALANCE_HISTORY = "tokenbalancehistory";
    public const string TOKEN_INFO = "tokeninfo";
    public const string ADDRESS_TOKEN_BALANCE = "addresstokenbalance";
    public const string ADDRESS_TOKEN_NFT_BALANCE = "addresstokennftbalance";
    public const string ADDRESS_TOKEN_NFT_INVENTORY = "addresstokennftinventory";
}

/// <summary>
/// BscScan Gas Tracker Module Actions
/// </summary>
internal static class GasTrackerModuleAction
{
    public const string GAS_ORACLE = "gasoracle";
    public const string DAILY_AVG_GAS_LIMIT = "dailyavggaslimit";
    public const string DAILY_GAS_USED = "dailygasused";
    public const string DAILY_AVG_GAS_PRICE = "dailyavggasprice";
}

/// <summary>
///  BscScan Gas Stats Module Actions
/// </summary>
internal static class GasStatsModuleAction
{
    public const string BNB_SUPPLY = "bnbsupply";
    public const string VALIDATOR_LIST = "validators";
    public const string BNB_PRICE = "bnbprice";
    public const string BNB_DAILY_PRICE = "bnbdailyprice";
    public const string DAILY_TXN_FEE = "dailytxnfee";
    public const string DAILY_NEW_ADDRESS = "dailynewaddress";
    public const string DAILY_NET_UTILIZATION = "dailynetutilization";
    public const string DAILY_TX = "dailytx";
}

/// <summary>
/// BscScan shared Query Params
/// </summary>
internal static class BscQueryParam
{
    public const string TxHash = "txhash={value}";
    public const string Address = "address={value}";
    public const string BlockNo = "blockno={value}";
    public const string BlockType = "blocktype={value}";
    public const string Timestamp = "timestamp={value}";
    public const string Closest = "closest={value}";
    public const string Tag = "tag={value}";
    public const string Boolean = "boolean={value}";
    public const string Index = "index={value}";
    public const string Hex = "hex={value}";
    public const string To = "to={value}";
    public const string Data = "data={value}";
    public const string Position = "position={value}";
    public const string ContractAddress = "contractaddress={value}";
}

internal static class MimeTypes
{
    public const string ApplicationJson = "application/json";
}
