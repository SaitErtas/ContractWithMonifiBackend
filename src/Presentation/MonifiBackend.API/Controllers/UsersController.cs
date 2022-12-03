using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.UserModule.Application.Notifications.Commands.CreateNotification;
using MonifiBackend.UserModule.Application.Notifications.Commands.MarkAsRead;
using MonifiBackend.UserModule.Application.Notifications.Queries.GetNotifications;
using MonifiBackend.UserModule.Application.Users.Commands.ConfirmUser;
using MonifiBackend.UserModule.Application.Users.Commands.RegistrationCompletion;
using MonifiBackend.UserModule.Application.Users.Commands.StatusChange;
using MonifiBackend.UserModule.Application.Users.Commands.UpdateLanguage;
using MonifiBackend.UserModule.Application.Users.Commands.UpdatePassword;
using MonifiBackend.UserModule.Application.Users.Commands.UpdateUser;
using MonifiBackend.UserModule.Application.Users.Events.RegisterFakeUser;
using MonifiBackend.UserModule.Application.Users.Queries.GetNetworkUsers;
using MonifiBackend.UserModule.Application.Users.Queries.GetUser;
using MonifiBackend.UserModule.Application.Users.Queries.GetUsers;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.WalletModule.Application.AccountMovements.Queries.BscScanAddress;
using MonifiBackend.WalletModule.Application.AccountMovements.Queries.BscScanNormalTransaction;

namespace MonifiBackend.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class UsersController : BaseApiController
{
    private readonly IMediator _mediator;
    public UsersController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [HttpGet("me")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> MeAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new GetUserQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpGet("notifications")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> NotificationsAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new GetNotificationsQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpPost("notifications")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> CreateNotificationsAsync(CreateNotificationCommand request)
    {
        var currentUser = (User)HttpContext.Items["User"];

        request.UserId = currentUser.Id;
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpPut("notifications/markasread")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> CreateNotificationsAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new MarkAsReadCommand(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpGet("network")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> NetworkAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];

        var request = new GetNetworkUsersQuery(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [AllowAnonymous]
    [HttpGet("confirm/{confirmationCode}")]
    public async Task<IActionResult> ConfirmAsync(string confirmationCode)
    {
        var request = new ConfirmUserCommand(confirmationCode);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpPost("registration-completion")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> RegistrationCompletionAsync([FromBody] RegistrationCompletionCommand request)
    {
        var currentUser = (User)HttpContext.Items["User"];
        request.UserId = currentUser.Id;
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpPost("BscScanAddress/{address}")]
    [AllowAnonymous]
    public async Task<IActionResult> BscScanAddressAsync(string address)
    {
        var request = new BscScanAddressQuery(address);
        var result = await _mediator.Send(request);
        return Ok(result);
    }
    [HttpPost("BscScanNormalTransaction/{address}")]
    [AllowAnonymous]
    public async Task<IActionResult> BscScanNormalTransactionAsync(string address)
    {
        var request = new BscScanNormalTransactionQuery(address);
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpPut("update-user")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> UpdateUserAsync([FromBody] UpdateUserCommand request)
    {
        var currentUser = (User)HttpContext.Items["User"];
        request.UserId = currentUser.Id;
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpPut("update-language")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> UpdateLanguageAsync([FromBody] UpdateLanguageCommand request)
    {
        var currentUser = (User)HttpContext.Items["User"];
        request.UserId = currentUser.Id;
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpGet("update-password")]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> UpdatePasswordAsync()
    {
        var currentUser = (User)HttpContext.Items["User"];
        var request = new UpdatePasswordCommand(currentUser.Id);
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [AllowAnonymous]
    [HttpGet("register-add-user-event")]
    public async Task<IActionResult> RegisterFakeUserEventAsync()
    {
        var request = new RegisterFakeUserEvent();
        await _mediator.Publish(request);
        return Ok();
    }

    [HttpPut("status-change")]
    [Authorize(Role.Administrator)]
    public async Task<IActionResult> StatusChangeAsync([FromBody] StatusChangeCommand request)
    {
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [HttpGet]
    [Authorize(Role.Administrator)]
    public async Task<IActionResult> GetUsersAsync()
    {
        var request = new GetUsersQuery();
        var result = await _mediator.Send(request);
        return Ok(result);
    }
}
