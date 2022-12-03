using Microsoft.AspNetCore.Mvc;

namespace MonifiBackend.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HealthController : ControllerBase
    {
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            return Ok();
        }
        [HttpGet("version")]
        public async Task<IActionResult> Version()
        {
            return Ok("2.0.1");
        }
    }
}
