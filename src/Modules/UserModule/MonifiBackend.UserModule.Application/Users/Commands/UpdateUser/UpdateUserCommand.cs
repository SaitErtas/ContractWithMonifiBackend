using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using System.Text.Json.Serialization;

namespace MonifiBackend.UserModule.Application.Users.Commands.UpdateUser;

public class UpdateUserCommand : ICommand<UpdateUserCommandResponse>
{
    public UpdateUserCommand(int userId, string username, string fullName, string walletAddress, int cryptoNetworkId, string phone, int countryId, int languageId)
    {
        UserId = userId;
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

internal class UpdateUserCommandValidator : AbstractValidator<UpdateUserCommand>
{
    public UpdateUserCommandValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Username))}");
        RuleFor(x => x.FullName)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.FullName))}");
        RuleFor(x => x.Phone)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.Phone))}");
        RuleFor(x => x.CountryId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.CountryId))}");
        RuleFor(x => x.LanguageId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.LanguageId))}");
    }
}