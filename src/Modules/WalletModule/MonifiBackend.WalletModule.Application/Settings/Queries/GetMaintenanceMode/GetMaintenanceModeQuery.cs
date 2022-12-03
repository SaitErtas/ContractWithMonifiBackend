using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Settings.Queries.GetMaintenanceMode;

public class GetMaintenanceModeQuery : IQuery<GetMaintenanceModeQueryResponse>
{

}
internal class GetSystemStatusQueryValidator : AbstractValidator<GetMaintenanceModeQuery>
{
    public GetSystemStatusQueryValidator()
    {
    }
}