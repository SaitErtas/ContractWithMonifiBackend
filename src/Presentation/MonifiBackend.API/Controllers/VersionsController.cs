using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.UserModule.Application.Versions.Queries.GetVersions;

namespace MonifiBackend.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class VersionsController : BaseApiController
{
    private readonly IMediator _mediator;
    public VersionsController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [AllowAnonymous]
    [HttpGet]
    public async Task<IActionResult> GetVersionsAsync()
    {
        var request = new GetVersionsQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }
}
