using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using MonifiBackend.UserModule.Application.Users.Commands.RegisterUser;
using System.Reflection;

namespace MonifiBackend.UserModule.Application
{
    public static class UserApplicationSetup
    {
        public static IServiceCollection AddUserServiceApplication(this IServiceCollection services)
        {
            services.AddMediatR(typeof(RegisterUserCommand).GetTypeInfo().Assembly);
            services.AddValidatorsFromAssembly(typeof(RegisterUserCommand).Assembly);

            return services;
        }
    }
}
