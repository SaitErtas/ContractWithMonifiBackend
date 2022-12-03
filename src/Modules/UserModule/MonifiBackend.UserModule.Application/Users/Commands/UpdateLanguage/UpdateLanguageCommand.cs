using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.UserModule.Application.Users.Commands.UpdateLanguage;

public class UpdateLanguageCommand : ICommand<UpdateLanguageCommandResponse>
{
    public UpdateLanguageCommand(int userId, int languageId)
    {
        UserId = userId;
        LanguageId = languageId;
    }
    [JsonIgnore]
    public int UserId { get; set; }
    public int LanguageId { get; set; }
}

internal class UpdateLanguageCommandValidator : AbstractValidator<UpdateLanguageCommand>
{
    public UpdateLanguageCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
        RuleFor(x => x.LanguageId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.LanguageId))}");
    }
}
