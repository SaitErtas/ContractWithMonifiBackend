using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.PackageModule.Application.Packages.Commands.DeletePackage;

public class DeletePackageCommand : ICommand<DeletePackageCommandResponse>
{
    public DeletePackageCommand(int id)
    {
        Id = id;
    }
    [JsonIgnore]
    public int Id { get; private set; }
}

internal class DeletePackageCommandValidator : AbstractValidator<DeletePackageCommand>
{
    public DeletePackageCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Id)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Id))}");
    }
}