using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.UserModule.Application.Users.Commands.Fa2Auth;

public class Fa2AuthCommand : ICommand<Fa2AuthCommandResponse>
{
    public Fa2AuthCommand(string email, string fa2Code,string metamaskWalletAddress)
    {
        Email = email;
        Fa2Code = fa2Code;
        MetamaskWalletAddress = metamaskWalletAddress;
    }
    public string Email { get; set; }
    public string Fa2Code { get; set; }
    public string MetamaskWalletAddress { get; set; }
    [JsonIgnore]
    public string IpAddress { get; private set; }
    public void SetIpAddress(string ipAddress)
    {
        IpAddress = ipAddress;
    }
}

internal class Fa2AuthCommandValidator : AbstractValidator<Fa2AuthCommand>
{
    public Fa2AuthCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        //RuleFor(x => x.Email)
        //    .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Email))}");
        //RuleFor(x => x.Fa2Code)
        //    .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Fa2Code))}");

    }
}