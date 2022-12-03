using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.UserModule.Application.Users.Commands.ChangedPassword;
using MonifiBackend.UserModule.Application.Users.Commands.Fa2Auth;
using MonifiBackend.UserModule.Application.Users.Commands.RegisterUser;
using MonifiBackend.UserModule.Application.Users.Commands.ResetPassword;
using MonifiBackend.UserModule.Application.Users.Queries.AuthenticateUser;
using Swashbuckle.AspNetCore.Annotations;

namespace MonifiBackend.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[SwaggerTag("Integration information with Auth transactions.")]
[ApiController]
public class AuthController : BaseApiController
{
    private readonly IMediator _mediator;
    public AuthController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [AllowAnonymous]
    [HttpPost("fa2auth")]
    public async Task<IActionResult> LoginAsync([FromBody] Fa2AuthCommand request)
    {
        request.SetIpAddress(Request.HttpContext.Connection.RemoteIpAddress.ToString());

        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> LoginAsync([FromBody] AuthenticateUserQuery request)
    {
        request.SetIpAddress(Request.HttpContext.Connection.RemoteIpAddress.ToString());

        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [AllowAnonymous]
    [HttpPost("signup")]
    public async Task<IActionResult> SignupAsync([FromBody] RegisterUserCommand request)
    {
        request.SetIpAddress(Request.HttpContext.Connection.RemoteIpAddress.ToString());
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [AllowAnonymous]
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPasswordAsync([FromBody] ResetPasswordCommand request)
    {
        var result = await _mediator.Send(request);
        return Ok(result);
    }

    [AllowAnonymous]
    [HttpPost("reset-password-confirm")]
    public async Task<IActionResult> ResetPasswordConfirmAsync([FromBody] ChangedPasswordCommand request)
    {
        var result = await _mediator.Send(request);
        return Ok(result);
    }
}
