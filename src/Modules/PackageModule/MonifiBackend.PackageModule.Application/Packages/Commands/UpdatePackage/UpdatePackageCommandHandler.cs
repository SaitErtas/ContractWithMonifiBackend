using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.PackageModule.Domain.Packages;

namespace MonifiBackend.PackageModule.Application.Packages.Commands.UpdatePackage;

internal class UpdatePackageCommandHandler : ICommandHandler<UpdatePackageCommand, UpdatePackageCommandResponse>
{
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly IPackageCommandDataPort _packageCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public UpdatePackageCommandHandler(IPackageQueryDataPort packageQueryDataPort, IPackageCommandDataPort packageCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _packageQueryDataPort = packageQueryDataPort;
        _packageCommandDataPort = packageCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<UpdatePackageCommandResponse> Handle(UpdatePackageCommand request, CancellationToken cancellationToken)
    {
        var package = await _packageQueryDataPort.GetPackageAsync(request.Id);
        AppRule.ExistsAndActive(package, new BusinessValidationException(BusinessValidationMessageType.NOT_FOUND, nameof(request.Id), request.Id));

        package.SetMinValue(request.MinValue);
        package.SetMaxValue(request.MaxValue);

        var status = await _packageCommandDataPort.SaveAsync(package);
        AppRule.True(status, new BusinessValidationException(BusinessValidationMessageType.NOT_UPDATED, nameof(request.Id), request.Id));

        return new UpdatePackageCommandResponse();
    }
}