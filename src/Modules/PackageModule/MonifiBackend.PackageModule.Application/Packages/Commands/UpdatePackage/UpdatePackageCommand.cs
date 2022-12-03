using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.PackageModule.Application.Packages.Commands.UpdatePackage;

public class UpdatePackageCommand : ICommand<UpdatePackageCommandResponse>
{
    [JsonIgnore]
    public int Id { get; set; }
    public int MinValue { get; set; }
    public int MaxValue { get; set; }
}

internal class UpdatePackageCommandValidator : AbstractValidator<UpdatePackageCommand>
{
    public UpdatePackageCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Id)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Id))}");
        RuleFor(x => x.MinValue)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.MinValue))}");
        RuleFor(x => x.MaxValue)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.MaxValue))}");
    }
}