using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.UserModule.Application.Users.Commands.ConfirmUser;

public class ConfirmUserCommand : ICommand<ConfirmUserCommandResponse>
{
    public ConfirmUserCommand(string confirmationCode)
    {
        ConfirmationCode = confirmationCode;
    }
    public string ConfirmationCode { get; set; }
}

internal class ConfirmUserCommandValidator : AbstractValidator<ConfirmUserCommand>
{
    public ConfirmUserCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.ConfirmationCode)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.ConfirmationCode))}");
    }
}