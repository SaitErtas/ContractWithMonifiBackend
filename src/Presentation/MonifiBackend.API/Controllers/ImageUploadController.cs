using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.Controllers.Base;
using MonifiBackend.API.ViewModels;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class ImageUploadController : BaseApiController
{
    public static IWebHostEnvironment _environment;
    private readonly ApplicationSettings _appSettings;
    private readonly Microsoft.AspNetCore.Hosting.IHostingEnvironment _hostingEnvironment;
    public ImageUploadController(IWebHostEnvironment environment, IOptions<ApplicationSettings> appSettings, Microsoft.AspNetCore.Hosting.IHostingEnvironment hostingEnvironment)
    {
        _environment = environment;
        _hostingEnvironment = hostingEnvironment;
        _appSettings = appSettings.Value;
    }
    [HttpPost, DisableRequestSizeLimit]
    [Authorize(Role.Administrator, Role.Owner, Role.User)]
    public async Task<IActionResult> Post([FromForm] FileUploadAPI objFile)
    {
        string result = "";
        var filename = $"{Guid.NewGuid()}.jpg";
        try
        {
            if (objFile.files.Length > 0)
            {
                if (!Directory.Exists(_environment.WebRootPath + "\\Upload"))
                {
                    Directory.CreateDirectory(_environment.WebRootPath + "\\Upload\\");
                }
                using (FileStream filestream = System.IO.File.Create(_environment.WebRootPath + "\\Upload\\" + filename))
                {
                    objFile.files.CopyTo(filestream);
                    filestream.Flush();
                    result = $"{_appSettings.ServiceAddress.BackendAddress}/Upload/{filename}";
                }
            }
        }
        catch (Exception ex)
        {
            throw;
        }
        return Ok(result);
    }
    //[HttpGet("social")]
    //[Authorize(Role.Administrator, Role.Owner, Role.User)]
    //public async Task<IActionResult> HtmlToImage()
    //{
    //    string result = "";
    //    var filename = $"{Guid.NewGuid()}.jpg";
    //    var converter = new HtmlConverter();
    //    string filePath = Directory.GetCurrentDirectory() + "\\wwwroot\\Templates\\Kupon.html";
    //    StreamReader str = new StreamReader(filePath);
    //    string html = str.ReadToEnd();
    //    var byteArrayIn = converter.FromHtmlString(html);
    //    Stream image = new MemoryStream(byteArrayIn);
    //    if (!Directory.Exists(_environment.WebRootPath + "\\Upload"))
    //    {
    //        Directory.CreateDirectory(_environment.WebRootPath + "\\Upload\\");
    //    }
    //    using (FileStream filestream = System.IO.File.Create(_environment.WebRootPath + "\\Upload\\" + filename))
    //    {
    //        image.CopyTo(filestream);
    //        filestream.Flush();
    //        result = $"{_appSettings.ServiceAddress.BackendAddress}/Upload/{filename}";
    //    }
    //    return Ok(result);
    //}
}
