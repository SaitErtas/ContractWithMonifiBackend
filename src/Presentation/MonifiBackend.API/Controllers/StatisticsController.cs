using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.WalletModule.Application.Statistics.Queries.GetAccountActivities;
using MonifiBackend.WalletModule.Application.Statistics.Queries.GetAdminStatistics;

namespace MonifiBackend.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class StatisticsController : BaseApiController
{
    private readonly IMediator _mediator;
    public StatisticsController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [Authorize(Role.Administrator)]
    [HttpGet("account-activities")]
    public async Task<IActionResult> AccountActivitiesAsync()
    {
        var request = new GetAccountActivitiesQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [Authorize(Role.Administrator)]
    [HttpGet("admin-statistics")]
    public async Task<IActionResult> AdminStatisticsAsync()
    {
        var request = new GetAdminStatisticsQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }
}
