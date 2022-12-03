using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel.DataAnnotations;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetUser
{
    public class GetUserQuery : IQuery<GetUserQueryResponse>
    {
        public GetUserQuery(int userId)
        {
            UserId = userId;
        }
        [Required]
        [SwaggerSchema(Nullable = false)]
        public int UserId { get; }

    }
    internal class GetUserQueryValidator : AbstractValidator<GetUserQuery>
    {
        public GetUserQueryValidator(IStringLocalizer<Resource> stringLocalizer)
        {
            RuleFor(x => x.UserId)
                .NotEmpty().WithMessage(x => $"{string.Format(stringLocalizer["FieldRequired"], nameof(x.UserId))}");

        }
    }
}
