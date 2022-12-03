using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.UserModule.Application.Users.Commands.RegisterUser;

public class RegisterUserCommand : ICommand<RegisterUserCommandResponse>
{
    public RegisterUserCommand(string email, string password, bool terms, string referenceCode)
    {
        Email = email;
        Password = password;
        Terms = terms;
        ReferenceCode = referenceCode;
    }
    public string Email { get; set; }
    public string Password { get; set; }
    public bool Terms { get; set; }
    public string ReferenceCode { get; set; }
    [JsonIgnore]
    public string IpAddress { get; private set; }
    public void SetIpAddress(string ipAddress)
    {
        IpAddress = ipAddress;
    }
}

internal class RegisterUserCommandValidator : AbstractValidator<RegisterUserCommand>
{
    public RegisterUserCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Email))}");
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Password))}");
        RuleFor(x => x.Terms)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Terms))}");
        RuleFor(x => x.ReferenceCode)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.ReferenceCode))}");

    }
}
