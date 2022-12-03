using Microsoft.AspNetCore.Mvc;
using MonifiBackend.Core.Domain.Responses;

namespace MonifiBackend.API.Controllers.Base;

[ApiController]
[Route("api/v1/[controller]")]
public class BaseApiController : ControllerBase
{
    public OkObjectResult Ok<T>(T data) => new OkObjectResult(new ResponseWrapper<T>(data));
}
