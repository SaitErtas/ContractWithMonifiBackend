using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.UserModule.Application.Notifications.Commands.MarkAsRead;

public class MarkAsReadCommand : ICommand<MarkAsReadCommandResponse>
{
    public MarkAsReadCommand(int userId)
    {
        UserId = userId;
    }
    [JsonIgnore]
    public int UserId { get; set; }
}

internal class MarkAssReadCommandValidator : AbstractValidator<MarkAsReadCommand>
{
    public MarkAssReadCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
    }
}