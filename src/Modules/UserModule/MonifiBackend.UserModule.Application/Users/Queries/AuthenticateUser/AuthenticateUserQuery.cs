using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace MonifiBackend.UserModule.Application.Users.Queries.AuthenticateUser;

public class AuthenticateUserQuery : IQuery<AuthenticateUserQueryResponse>
{
    public AuthenticateUserQuery(string email, string password)
    {
        Email = email;
        Password = password;
    }
    [Required]
    [SwaggerSchema(Nullable = false)]
    public string Email { get; }

    [Required]
    [SwaggerSchema(Nullable = false)]
    public string Password { get; }
    [JsonIgnore]
    public string IpAddress { get; private set; }
    public void SetIpAddress(string ipAddress)
    {
        IpAddress = ipAddress;
    }
}
internal class AuthenticateUserQueryValidator : AbstractValidator<AuthenticateUserQuery>
{
    public AuthenticateUserQueryValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Email))}");
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Password))}");
    }
}
