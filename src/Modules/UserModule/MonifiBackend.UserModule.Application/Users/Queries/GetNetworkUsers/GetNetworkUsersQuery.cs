using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetNetworkUsers;

public class GetNetworkUsersQuery : IQuery<GetNetworkUsersQueryResponse>
{
    public GetNetworkUsersQuery(int userId)
    {
        UserId = userId;
    }
    public int UserId { get; }

}
internal class GetNetworkUsersQueryValidator : AbstractValidator<GetNetworkUsersQuery>
{
    public GetNetworkUsersQueryValidator(IStringLocalizer<Resource> stringLocalizer)
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");
    }
}