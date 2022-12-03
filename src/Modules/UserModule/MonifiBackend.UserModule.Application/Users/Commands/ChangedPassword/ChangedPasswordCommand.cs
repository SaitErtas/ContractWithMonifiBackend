using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.UserModule.Application.Users.Commands.ChangedPassword;

public class ChangedPasswordCommand : ICommand<ChangedPasswordCommandResponse>
{
    public string Email { get; set; }
    public string ResetPasswordCode { get; set; }
    public string NewPassword { get; set; }
}
internal class ChangedPasswordCommandValidator : AbstractValidator<ChangedPasswordCommand>
{
    public ChangedPasswordCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.ResetPasswordCode)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.ResetPasswordCode))}");
        RuleFor(x => x.NewPassword)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.NewPassword))}");
    }
}