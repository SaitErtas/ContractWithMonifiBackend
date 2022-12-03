using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.UserModule.Application.Wallets.Queries.GetNetworks;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.WalletModule.Application.AccountMovements.Commands.BuyMonofi;
using MonifiBackend.WalletModule.Application.AccountMovements.Commands.DeleteAccountMovement;
using MonifiBackend.WalletModule.Application.AccountMovements.Commands.TransferAccept;
using MonifiBackend.WalletModule.Application.AccountMovements.Events.AllPaymentVerification;
using MonifiBackend.WalletModule.Application.AccountMovements.Events.FakeMovement;
using MonifiBackend.WalletModule.Application.AccountMovements.Events.UserPaymentVerification;
using MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetAccountMovements;
using MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetNoBonusPurchasedMovements;
using MonifiBackend.WalletModule.Application.AccountMovements.Queries.GetPurchasedMovements;
using MonifiBackend.WalletModule.Application.AccountMovements.Queries.TransferCheck;
using MonifiBackend.WalletModule.Application.Statistics.Queries.ApyAnalysis;
using MonifiBackend.WalletModule.Application.Statistics.Queries.EarningsPages;
using MonifiBackend.WalletModule.Application.Statistics.Queries.GetDaySaleStatistics;
using MonifiBackend.WalletModule.Application.Statistics.Queries.GetStatistic;

namespace MonifiBackend.API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class WalletsController : BaseApiController
{
    private readonly IMediator _mediator;
    public WalletsController(IMediator mediator)
    {
        _mediator = mediator;
    }
    [HttpPost("BuyMonifi")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> BuyMonifiAsync([FromBody] BuyMonofiCommand request)
    {
        request.SetIpAddress(Request.HttpContext.Connection.RemoteIpAddress.ToString());

        var currentUser = (User)HttpContext.Items["User"];
        request.UserId = currentUser.Id;
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpGet("account-movements")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> GetAccountMovementsAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new GetAccountMovementsQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpGet("purchased-movements")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> GetPurchasedMovementsAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new GetPurchasedMovementsQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpGet("nobonus-purchased-movements")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> GetNoBonusPurchasedMovementsAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new GetNoBonusPurchasedMovementsQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [AllowAnonymous]
    [HttpGet("networks")]
    public async Task<IActionResult> GetNetworksAsync()
    {
        var request = new GetNetworksQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpGet("statistics")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> GetStatisticsAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new GetStatisticsQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpGet("day-sale-statistics")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> GetDaySaleStatisticsAsync()
    {
        var request = new GetDaySaleStatisticsQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }


    [HttpGet("user-payment-sync")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> UserPaymentSyncAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new UserPaymentVerificationEvent(currentUser.Id);
        await _mediator.Publish(request);
        return Ok();
    }

    [HttpDelete("{accountMovementId}")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> DeleteAccountMovementAsync(int accountMovementId)
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new DeleteAccountMovementCommand(currentUser.Id, accountMovementId);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpGet("apy-analysis")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> ApyAnalysisAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new ApyAnalysisQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpGet("earnings-page")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> EarningsPagesAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new EarningsPagesQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [AllowAnonymous]
    [HttpGet("all-payment-verification")]
    public async Task<IActionResult> AllPaymentVerificationAsync()
    {
        var request = new AllPaymentVerificationEvent();
        await _mediator.Publish(request);
        return Ok();
    }
    [AllowAnonymous]
    [HttpGet("add-movement")]
    public async Task<IActionResult> FakeMovementAsync()
    {
        var request = new FakeMovementEvent();
        await _mediator.Publish(request);
        return Ok();
    }

    [HttpGet("transfer-check/{email}")]
    [Authorize(Role.Administrator)]
    public async Task<IActionResult> TransferCheckAsync(string email)
    {
        var request = new TransferCheckQuery(email);
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpPost("transfer-accept/{email}")]
    [Authorize(Role.Administrator)]
    public async Task<IActionResult> TransferAcceptAsync(string email)
    {
        var request = new TransferAcceptCommand(email);
        var result = await _mediator.Send(request);
        return Ok(result);
    }

}
