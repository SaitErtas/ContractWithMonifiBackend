using MediatR;
using Microsoft.AspNetCore.Mvc;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.WalletModule.Application.Settings.Commands.UpdateSetting;
using MonifiBackend.WalletModule.Application.Settings.Queries.GetMaintenanceMode;
using MonifiBackend.WalletModule.Application.Settings.Queries.GetSettings;

namespace MonifiBackend.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class SettingsController : BaseApiController
    {
        private readonly IMediator _mediator;
        public SettingsController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpGet("maintenance-mode")]
        [AllowAnonymous]
        public async Task<IActionResult> GetMaintenanceModeAsync()
        {
            var request = new GetMaintenanceModeQuery();
            var result = await _mediator.Send(request);
            return Ok(result);
        }

        [HttpGet]
        [Authorize(Role.Administrator)]
        public async Task<IActionResult> GetSettingsAsync()
        {
            var request = new GetSettingsQuery();
            var result = await _mediator.Send(request);
            return Ok(result);
        }

        [HttpPut]
        [Authorize(Role.Administrator)]
        public async Task<IActionResult> UpdateSettingAsync([FromBody] UpdateSettingCommand request)
        {
            var result = await _mediator.Send(request);
            return Ok(result);
        }


    }
}
