using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.PackageDetailModule.Domain.PackageDetails;
using MonifiBackend.PackageModule.Domain.Packages;

namespace MonifiBackend.PackageModule.Application.Packages.Commands.CreatePackage;

internal class CreatePackageCommandHandler : ICommandHandler<CreatePackageCommand, CreatePackageCommandResponse>
{
    private readonly IPackageQueryDataPort _packageQueryDataPort;
    private readonly IPackageCommandDataPort _packageCommandDataPort;
    private readonly IStringLocalizer<Resource> _stringLocalizer;

    public CreatePackageCommandHandler(IPackageQueryDataPort packageQueryDataPort, IPackageCommandDataPort packageCommandDataPort, IStringLocalizer<Resource> stringLocalizer)
    {
        _packageQueryDataPort = packageQueryDataPort;
        _packageCommandDataPort = packageCommandDataPort;
        _stringLocalizer = stringLocalizer;
    }

    public async Task<CreatePackageCommandResponse> Handle(CreatePackageCommand request, CancellationToken cancellationToken)
    {
        var package = Package.CreateNew(request.Name, request.MinValue, request.MaxValue, request.ChangePeriodDay, request.Icon, request.Bonus, BaseStatus.Active);
        foreach (var detail in request.Details)
        {
            package.AddDetail(PackageDetail.CreateNew(detail.Name, detail.Duration, detail.Commission, BaseStatus.Active));
        }
        var packageId = await _packageCommandDataPort.CreateAsync(package);
        AppRule.NotNegativeOrZero(packageId, new BusinessValidationException(BusinessValidationMessageType.NOT_CREATED, nameof(request.Name), request.Name));

        return new CreatePackageCommandResponse();
    }
}