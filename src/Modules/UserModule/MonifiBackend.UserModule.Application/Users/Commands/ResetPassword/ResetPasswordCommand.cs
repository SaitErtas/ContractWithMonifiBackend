using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.UserModule.Application.Users.Commands.ResetPassword;

public class ResetPasswordCommand : ICommand<ResetPasswordCommandResponse>
{
    public string Email { get; set; }
}
internal class ResetPasswordCommandValidator : AbstractValidator<ResetPasswordCommand>
{
    public ResetPasswordCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Email))}");
    }
}