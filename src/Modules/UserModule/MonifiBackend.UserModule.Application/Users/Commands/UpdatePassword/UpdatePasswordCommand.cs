using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.UserModule.Application.Users.Commands.UpdatePassword;

public class UpdatePasswordCommand : ICommand<UpdatePasswordCommandResponse>
{
    public UpdatePasswordCommand(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; set; }
}
internal class UpdatePasswordCommandValidator : AbstractValidator<UpdatePasswordCommand>
{
    public UpdatePasswordCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
    }
}