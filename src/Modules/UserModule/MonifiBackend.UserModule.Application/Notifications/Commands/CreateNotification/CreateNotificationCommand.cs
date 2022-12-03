using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.UserModule.Application.Notifications.Commands.CreateNotification;

public class CreateNotificationCommand : ICommand<CreateNotificationCommandResponse>
{
    public CreateNotificationCommand(int userId, string message)
    {
        UserId = userId;
        Message = message;
    }
    [JsonIgnore]
    public int UserId { get; set; }
    public string Message { get; set; }
}

internal class CreateNotificationCommandValidator : AbstractValidator<CreateNotificationCommand>
{
    public CreateNotificationCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
        RuleFor(x => x.Message)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Message))}");
    }
}