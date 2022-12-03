using CoreHtmlToImage;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.WalletModule.Domain.AccountMovements;
using MonifiBackend.WalletModule.Domain.Settings;
using MonifiBackend.WalletModule.Domain.Users;

namespace MonifiBackend.WalletModule.Application.Statistics.Queries.EarningsPages;

internal class EarningsPagesQueryHandler : IQueryHandler<EarningsPagesQuery, EarningsPagesQueryResponse>
{
    private const int DEFAULT_SETTING_VALUE = 1;
    private readonly ISettingQueryDataPort _settingQueryDataPort;
    private readonly IAccountMovementQueryDataPort _accountMovementQueryDataPort;
    private readonly IUserQueryDataPort _userQueryDataPort;
    public static IWebHostEnvironment _environment;
    private readonly ApplicationSettings _appSettings;
    public EarningsPagesQueryHandler(IUserQueryDataPort userQueryDataPort, IAccountMovementQueryDataPort accountMovementQueryDataPort, ISettingQueryDataPort settingQueryDataPort, IWebHostEnvironment environment, IOptions<ApplicationSettings> appSettings)
    {
        _accountMovementQueryDataPort = accountMovementQueryDataPort;
        _settingQueryDataPort = settingQueryDataPort;
        _userQueryDataPort = userQueryDataPort;
        _environment = environment;
        _appSettings = appSettings.Value;
    }
    public async Task<EarningsPagesQueryResponse> Handle(EarningsPagesQuery request, CancellationToken cancellationToken)
    {
        var setting = await _settingQueryDataPort.GetAsync(DEFAULT_SETTING_VALUE);
        var user = await _userQueryDataPort.GetUserAsync(request.UserId);
        var userBonus = await _userQueryDataPort.GetTotalBonusAsync(request.UserId);
        var userNotComission = await _userQueryDataPort.GetNotCommissionTotalSaleAsync(request.UserId);
        var userTotalSale = await _userQueryDataPort.GetTotalSaleAsync(request.UserId);
        var totalEarning = userTotalSale + userBonus;

        decimal percent = 0;
        if (userNotComission != 0)
            percent = (totalEarning / userNotComission) * 100;
        else if (userNotComission == 0)
            percent = totalEarning;

        var movements = await _accountMovementQueryDataPort.GetSaleMovementAsync(request.UserId, TransactionStatus.Successful);
        var firstTime = movements.OrderBy(o => o.TransferTime).FirstOrDefault()?.TransferTime;

        var kazanc = movements.Select(s => new { ExistDate = s.TransferTime.AddMonths(s.PackageDetail.Duration) }).ToList();
        var lastTime = kazanc.OrderByDescending(o => o.ExistDate).FirstOrDefault()?.ExistDate;


        string result = "";
        var filename = $"{Guid.NewGuid()}.jpg";
        var converter = new HtmlConverter();
        string filePath = Directory.GetCurrentDirectory() + "\\wwwroot\\Templates\\Kupon.html";
        StreamReader str = new StreamReader(filePath);
        string html = str.ReadToEnd();
        html = html
            .Replace("[totalEarning]", $"{Math.Round(totalEarning, 2)}")
            .Replace("[lastTime]", $"{lastTime}")
            .Replace("[percent]", $"{Math.Round(percent, 2)}")
            .Replace("[ReferanceCode]", $"{_appSettings.ServiceAddress.FrontendAddress}/register/?refCode={user.ReferanceCode}")
            .Replace("[MonifiPrice]", $"{Math.Round(setting.MonifiPrice, 3)}");
        var byteArrayIn = converter.FromHtmlString(html);
        Stream image = new MemoryStream(byteArrayIn);
        if (!Directory.Exists(_environment.WebRootPath + "\\Upload"))
        {
            Directory.CreateDirectory(_environment.WebRootPath + "\\Upload\\");
        }
        using (FileStream filestream = File.Create(_environment.WebRootPath + "\\Upload\\" + filename))
        {
            image.CopyTo(filestream);
            filestream.Flush();
            result = $"{_appSettings.ServiceAddress.BackendAddress}/Upload/{filename}";
        }

        return new EarningsPagesQueryResponse(result);
    }
}