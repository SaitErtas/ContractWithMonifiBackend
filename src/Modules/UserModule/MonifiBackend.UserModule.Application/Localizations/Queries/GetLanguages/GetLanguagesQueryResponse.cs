using MonifiBackend.UserModule.Domain.Localizations;

namespace MonifiBackend.UserModule.Application.Localizations.Queries.GetLanguages;

public class GetLanguagesQueryResponse
{
    public GetLanguagesQueryResponse(List<Language> languages)
    {
        Languages = languages.Select(x => new GetLanguage(x)).ToList();
        Count = languages.Count;

    }
    public List<GetLanguage> Languages { get; private set; }
    public int Count { get; private set; }
}
public class GetLanguage
{
    public GetLanguage(Language language)
    {
        Id = language.Id;
        Name = language.Name;
        NativeName = language.NativeName;
        ShortName = language.ShortName;
    }

    public int Id { get; private set; }
    public string Name { get; private set; }
    public string NativeName { get; private set; }
    public string ShortName { get; private set; }
}
