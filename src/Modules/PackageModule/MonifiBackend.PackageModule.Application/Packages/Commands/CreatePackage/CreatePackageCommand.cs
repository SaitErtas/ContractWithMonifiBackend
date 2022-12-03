using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.PackageModule.Application.Packages.Commands.CreatePackage;

public class CreatePackageCommand : ICommand<CreatePackageCommandResponse>
{
    public CreatePackageCommand(string name, int minValue, int maxValue, int changePeriodDay, string icon)
    {
        Name = name;
        MinValue = minValue;
        MaxValue = maxValue;
        ChangePeriodDay = changePeriodDay;
        Icon = icon;
    }
    public string Name { get; set; }
    public int MinValue { get; set; }
    public int MaxValue { get; set; }
    public int ChangePeriodDay { get; set; }
    public string Icon { get; set; }
    public int Bonus { get; set; }
    public List<CreatePackageDetail> Details { get; set; }
}

public class CreatePackageDetail
{
    public string Name { get; set; }
    public int Duration { get; set; }
    public int Commission { get; set; }
}
internal class CreatePackageCommandValidator : AbstractValidator<CreatePackageCommand>
{
    public CreatePackageCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Name)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Name))}");
        RuleFor(x => x.MinValue)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.MinValue))}");
        RuleFor(x => x.MaxValue)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.MaxValue))}");
        RuleFor(x => x.ChangePeriodDay)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.ChangePeriodDay))}");
        RuleFor(x => x.Icon)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Icon))}");
    }
}
