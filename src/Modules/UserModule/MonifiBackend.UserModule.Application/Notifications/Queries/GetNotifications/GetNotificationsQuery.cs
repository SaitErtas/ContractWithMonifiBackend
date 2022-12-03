using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel.DataAnnotations;

namespace MonifiBackend.UserModule.Application.Notifications.Queries.GetNotifications;

public class GetNotificationsQuery : IQuery<GetNotificationsQueryResponse>
{
    public GetNotificationsQuery(int userId)
    {
        UserId = userId;
    }
    [Required]
    [SwaggerSchema(Nullable = false)]
    public int UserId { get; }

}
internal class GetNotificationsQueryValidator : AbstractValidator<GetNotificationsQuery>
{
    public GetNotificationsQueryValidator()
    {
        RuleFor(x => x.UserId)
            .NotEmpty().WithMessage("UserId alanı boş bırakılamaz.");

    }
}