namespace MonifiBackend.WalletModule.Application.Statistics.Queries.EarningsPages;

public class EarningsPagesQueryResponse
{
    public EarningsPagesQueryResponse(string url)
    {
        Url = url;
    }

    public string Url { get; private set; }
}
