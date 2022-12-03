using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Settings.Queries.GetSettings;

public class GetSettingsQuery : IQuery<GetSettingsQueryResponse>
{

}
internal class GetSystemStatusQueryValidator : AbstractValidator<GetSettingsQuery>
{
    public GetSystemStatusQueryValidator()
    {
    }
}