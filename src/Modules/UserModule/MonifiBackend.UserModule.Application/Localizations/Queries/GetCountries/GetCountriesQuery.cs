using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Localizations.Queries.GetCountries;

public class GetCountriesQuery : IQuery<GetCountriesQueryResponse>
{
    public GetCountriesQuery()
    {
    }

}
internal class GetCountriesQueryValidator : AbstractValidator<GetCountriesQuery>
{
    public GetCountriesQueryValidator()
    {

    }
}