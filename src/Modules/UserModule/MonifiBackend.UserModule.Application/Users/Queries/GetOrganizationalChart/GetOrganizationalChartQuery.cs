using FluentValidation;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Infrastructure.Localize;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel.DataAnnotations;

namespace MonifiBackend.UserModule.Application.Users.Queries.GetOrganizationalCharts
{
    public class GetOrganizationalChartQuery : IQuery<GetOrganizationalChartQueryResponse>
    {
        public GetOrganizationalChartQuery(int userId, string userName, string userEmail)
        {
            UserId = userId;
            UserName = userName;
            UserEmail = userEmail;
        }

        [SwaggerSchema(Nullable = true)]
        public int UserId { get; }

        [SwaggerSchema(Nullable = true)]
        public string UserName { get; }

        [SwaggerSchema(Nullable = true)]
        public string UserEmail { get; }
    }

    internal class GetOrganizationQueryValidator : AbstractValidator<GetOrganizationalChartQuery>
    {
        public GetOrganizationQueryValidator(IStringLocalizer<Resource> stringLocalizer)
        {


        }
    }
}
