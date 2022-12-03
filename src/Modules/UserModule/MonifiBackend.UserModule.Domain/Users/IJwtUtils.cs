using System.IdentityModel.Tokens.Jwt;

namespace MonifiBackend.UserModule.Domain.Users
{
    public interface IJwtUtils
    {
        Task<JwtSecurityToken> GenerateJwtToken(User user);
        public int? ValidateJwtToken(string token);
    }
}
