using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.UserModule.Application.Localizations.Queries.GetCountries;
using MonifiBackend.UserModule.Application.Localizations.Queries.GetLanguages;

namespace MonifiBackend.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class LocalizationsController : BaseApiController
{
    private readonly IMediator _mediator;
    public LocalizationsController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [HttpGet("languages")]
    [AllowAnonymous]
    public async Task<IActionResult> GetLanguagesAsync()
    {
        var request = new GetLanguagesQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpGet("countries")]
    [AllowAnonymous]
    public async Task<IActionResult> GetCountriesAsync()
    {
        var request = new GetCountriesQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }
}
