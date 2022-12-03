using AspNetCoreRateLimit;
using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MonifiBackend.API.Authorization;
using MonifiBackend.API.HealthCheck;
using MonifiBackend.API.Services;
using MonifiBackend.Core.Infrastructure;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.Core.Infrastructure.Middlewares;
using MonifiBackend.PackageModule.Application;
using MonifiBackend.PackageModule.Infrastructure;
using MonifiBackend.UserModule.Application;
using MonifiBackend.UserModule.Infrastructure;
using MonifiBackend.WalletModule.Application;
using MonifiBackend.WalletModule.Infrastructure;
using Serilog;

var builder = WebApplication.CreateBuilder(args);


Log.Logger = new LoggerConfiguration().CreateBootstrapLogger();
builder.Host.UseSerilog(((ctx, lc) => lc
.ReadFrom.Configuration(ctx.Configuration)));


//---Services-Related Configurations---//
var _applicationSettings = new ApplicationSettings();

builder.Configuration.AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true);
builder.Configuration.AddEnvironmentVariables();

#region Settings
builder.Services.Configure<ApplicationSettings>(builder.Configuration.GetSection("ApplicationSettings"));
builder.Configuration.GetSection("ApplicationSettings").Bind(_applicationSettings);
#endregion

#region Core Setup
builder.Services.ConfigureCoreInfrastructure(_applicationSettings);
#endregion

#region User Setup
builder.Services.AddUserServiceApplication();
builder.Services.AddUserServiceInfrastructure();
#endregion

#region Package Setup
builder.Services.AddPackageServiceApplication();
builder.Services.AddPackageServiceInfrastructure();
#endregion

#region Wallet Setup
builder.Services.AddWalletServiceApplication();
builder.Services.AddWalletServiceInfrastructure();
#endregion

// Add services to the container.
builder.Services.AddHostedService<AllPaymentVerificationService>();
builder.Services.AddHostedService<CreateAccountMovementUserService>();
builder.Services.AddHostedService<RegisterUserService>();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1",
        new OpenApiInfo
        {
            Title = "Monifi Backend System Documentation",
            Version = "v1",
            Description = "This documantation Modular Monolith system.",
            Contact = new OpenApiContact
            {
                Name = "Monifi Backend",
                Email = "monifi@example.com"
            }
        });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = @"JWT Authorization header using the Bearer scheme. \r\n\r\n 
                      Enter 'Bearer' [space] and then your token in the text input below.
                      \r\n\r\nExample: 'Bearer 12345abcdef'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement()
      {
        {
          new OpenApiSecurityScheme
          {
            Reference = new OpenApiReference
              {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
              },
              Scheme = "oauth2",
              Name = "Bearer",
              In = ParameterLocation.Header,

            },
            new List<string>()
          }
        });
    //var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    //var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    //options.IncludeXmlComments(xmlPath);
});


builder.Services.AddHealthChecks()
    .AddSqlServer(builder.Configuration.GetSection("ApplicationSettings:MssqlSettings:ConnectionStrings").Value, tags: new[] { "database" })
    .AddCheck<MyHealthCheck>("MyHealthCheck", tags: new[] { "custom" }); ;
builder.Services.AddHealthChecksUI().AddInMemoryStorage();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.MapHealthChecks("/health", new HealthCheckOptions
{
    Predicate = p => true,
    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
});
app.UseHealthChecksUI(options => { options.UIPath = "/health-dashboard"; });
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    options.SwaggerEndpoint("/swagger/v1/swagger.json",
    "Swagger Demo Documentation v1"));
    app.UseReDoc(options =>
    {
        options.DocumentTitle = "Swagger Demo Documentation";
        options.SpecUrl = "/swagger/v1/swagger.json";
    });

    app.UseReDoc(options =>
    {
        options.DocumentTitle = "Swagger Demo Documentation";
        options.SpecUrl = "/swagger/v1/swagger.json";
    });
}
app.UseMiddleware<ExceptionMiddleware>();
// custom jwt auth middleware
app.UseMiddleware<JwtMiddleware>();
app.UseIpRateLimiting();

// global cors policy
app.UseCors(x => x
    .AllowAnyMethod()
    .AllowAnyHeader()
    .SetIsOriginAllowed(origin => true) // allow any origin
    .AllowCredentials()); // allow credentials

var localizationOptions = app.Services.GetService<IOptions<RequestLocalizationOptions>>();
app.UseRequestLocalization(localizationOptions.Value);

app.UseStaticFiles();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.UseSerilogRequestLogging();

app.Run();
