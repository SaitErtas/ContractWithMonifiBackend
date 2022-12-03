using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.PackageModule.Application.Packages.Commands.CreatePackage;
using MonifiBackend.PackageModule.Application.Packages.Commands.DeletePackage;
using MonifiBackend.PackageModule.Application.Packages.Commands.UpdatePackage;
using MonifiBackend.PackageModule.Application.Packages.Queries.GetPackages;
using MonifiBackend.PackageModule.Application.Packages.Queries.GetPackagesDetails;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class PackagesController : BaseApiController
{
    private readonly IMediator _mediator;
    public PackagesController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [AllowAnonymous]
    [HttpGet("details")]
    public async Task<IActionResult> GetPackagesDetailsAsync()
    {
        var request = new GetPackagesDetailsQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [AllowAnonymous]
    [HttpGet]
    public async Task<IActionResult> GetPackagesAsync()
    {
        var request = new GetPackagesQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [Authorize(Role.Administrator)]
    [HttpPost]
    public async Task<IActionResult> CreatePackageAsync([FromBody] CreatePackageCommand request)
    {
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [Authorize(Role.Administrator)]
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdatePackageAsync([FromRoute] int id, [FromBody] UpdatePackageCommand request)
    {
        request.Id = id;
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [Authorize(Role.Administrator)]
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeletePackageAsync([FromRoute] int id)
    {
        var request = new DeletePackageCommand(id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
}
