using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.UserModule.Application.Users.Commands.StatusChange;

public class StatusChangeCommand : ICommand<StatusChangeCommandResponse>
{
    public StatusChangeCommand(int userId, int status)
    {
        UserId = userId;
        Status = status;
    }
    public int UserId { get; set; }
    public int Status { get; set; }
}

internal class StatusChangeCommandValidator : AbstractValidator<StatusChangeCommand>
{
    public StatusChangeCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
        RuleFor(x => x.Status)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Status))}");
    }
}