using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.WalletModule.Application.Bots.Commands.CreateBot;
using MonifiBackend.WalletModule.Application.Bots.Commands.DeleteBot;
using MonifiBackend.WalletModule.Application.Bots.Queries.GetBots;

namespace MonifiBackend.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class BotsController : BaseApiController
{
    private readonly IMediator _mediator;
    public BotsController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [HttpGet]
    [Authorize(Role.Administrator)]
    public async Task<IActionResult> GetBotsAsync()
    {
        var request = new GetBotsQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpPost]
    [Authorize(Role.Administrator)]
    public async Task<IActionResult> CreateBotAsync([FromBody] CreateBotCommand request)
    {
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpDelete("{id}")]
    [Authorize(Role.Administrator)]
    public async Task<IActionResult> DeletePackageAsync([FromRoute] int id)
    {
        var request = new DeleteBotCommand(id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
}