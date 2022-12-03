using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.WalletModule.Application.AccountMovements.Commands.BuyMonofi;

public class BuyMonofiCommand : ICommand<BuyMonofiCommandResponse>
{
    [JsonIgnore]
    public int UserId { get; set; }
    public decimal Amount { get; set; }
    public int PackageDetailId { get; set; }
    [JsonIgnore]
    public string IpAddress { get; private set; }
    public void SetIpAddress(string ipAddress)
    {
        IpAddress = ipAddress;
    }
}
internal class BuyMonofiCommandValidator : AbstractValidator<BuyMonofiCommand>
{
    public BuyMonofiCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
        RuleFor(x => x.Amount)
            .GreaterThan(0)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Amount))}");
        RuleFor(x => x.PackageDetailId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.PackageDetailId))}");
    }
}
