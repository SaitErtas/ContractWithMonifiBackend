using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.UserModule.Application.Users.Commands.RegistrationCompletion;

public class RegistrationCompletionCommand : ICommand<RegistrationCompletionCommandResponse>
{
    public RegistrationCompletionCommand(int userId, string username, string fullName, string walletAddress, int cryptoNetworkId, string phone, int countryId, int languageId)
    {
        Username = username;
        FullName = fullName;
        WalletAddress = walletAddress;
        CryptoNetworkId = cryptoNetworkId;
        Phone = phone;
        CountryId = countryId;
        LanguageId = languageId;
    }
    [JsonIgnore]
    public int UserId { get; set; }
    public string Username { get; set; }
    public string FullName { get; set; }
    public string WalletAddress { get; set; }
    public int CryptoNetworkId { get; set; }
    public string Phone { get; set; }
    public int CountryId { get; set; }
    public int LanguageId { get; set; }
}

internal class RegistrationCompletionCommandValidator : AbstractValidator<RegistrationCompletionCommand>
{
    public RegistrationCompletionCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Username))}");
        RuleFor(x => x.FullName)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.FullName))}");
        RuleFor(x => x.WalletAddress)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.WalletAddress))}");
        RuleFor(x => x.CryptoNetworkId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.CryptoNetworkId))}");
        RuleFor(x => x.Phone)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Phone))}");
        RuleFor(x => x.CountryId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.CountryId))}");
        RuleFor(x => x.LanguageId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.LanguageId))}");
    }
}