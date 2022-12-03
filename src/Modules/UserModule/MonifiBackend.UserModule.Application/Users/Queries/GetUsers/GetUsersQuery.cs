using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetUsers;

public class GetUsersQuery : IQuery<GetUsersQueryResponse>
{

}
internal class GetUsersQueryValidator : AbstractValidator<GetUsersQuery>
{
    public GetUsersQueryValidator(IStringLocalizer<Resource> stringLocalizer)
    {

    }
}