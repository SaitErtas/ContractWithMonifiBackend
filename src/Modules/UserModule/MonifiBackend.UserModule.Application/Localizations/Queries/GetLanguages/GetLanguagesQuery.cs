using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.UserModule.Application.Localizations.Queries.GetLanguages;

public class GetLanguagesQuery : IQuery<GetLanguagesQueryResponse>
{
    public GetLanguagesQuery()
    {
    }

}
internal class GetLanguagesQueryValidator : AbstractValidator<GetLanguagesQuery>
{
    public GetLanguagesQueryValidator()
    {

    }
}