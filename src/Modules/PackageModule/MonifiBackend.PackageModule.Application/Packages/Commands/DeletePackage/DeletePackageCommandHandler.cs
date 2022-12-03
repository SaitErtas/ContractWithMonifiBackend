using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.PackageModule.Domain.Packages;

namespace MonifiBackend.PackageModule.Application.Packages.Commands.DeletePackage;

internal class DeletePackageCommandHandler : ICommandHandler<DeletePackageCommand, DeletePackageCommandResponse>
{
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly IPackageCommandDataPort _packageCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public DeletePackageCommandHandler(IPackageQueryDataPort packageQueryDataPort, IPackageCommandDataPort packageCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _packageQueryDataPort = packageQueryDataPort;
        _packageCommandDataPort = packageCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<DeletePackageCommandResponse> Handle(DeletePackageCommand request, CancellationToken cancellationToken)
    {
        var package = await _packageQueryDataPort.GetPackageAsync(request.Id);
        AppRule.ExistsAndActive(package, new BusinessValidationException(BusinessValidationMessageType.NOT_FOUND, nameof(request.Id), request.Id));

        package.MarkAsDeleted();

        var status = await _packageCommandDataPort.SaveAsync(package);
        AppRule.True(status, new BusinessValidationException(BusinessValidationMessageType.NOT_CREATED, nameof(request.Id), request.Id));

        return new DeletePackageCommandResponse();
    }
}