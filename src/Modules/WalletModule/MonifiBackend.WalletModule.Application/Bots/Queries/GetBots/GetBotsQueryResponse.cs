using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.WalletModule.Domain.Bots;

namespace MonifiBackend.WalletModule.Application.Bots.Queries.GetBots;

public class GetBotsQueryResponse
{
    public GetBotsQueryResponse(List<Bot> bots)
    {
        Bots = bots.Select(s => new GetBotResponse(s)).ToList();
    }
    public List<GetBotResponse> Bots { get; set; }
}
public class GetBotResponse
{
    public GetBotResponse(Bot bot)
    {
        Id = bot.Id;
        Hour = bot.Hour;
        Minute = bot.Minute;
        WorkingRangeDesc = bot.WorkingRange.ToString();
        WorkingRange = bot.WorkingRange.ToInt();
        Range = bot.Range;
        RangeDesc = bot.Range.ToEnum<DayOfWeek>().ToString();
        Amount = bot.Amount;
        PackageDetailId = bot.PackageDetailId;
    }
    public int Id { get; private set; }
    public int Hour { get; private set; }
    public int Minute { get; private set; }
    public int WorkingRange { get; private set; }
    public string WorkingRangeDesc { get; private set; }
    public int Range { get; private set; }
    public string RangeDesc { get; private set; }
    public int Amount { get; private set; }
    public int PackageDetailId { get; private set; }
    public string ActionCommand { get; private set; } = "select";

}