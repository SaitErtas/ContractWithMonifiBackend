using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MonifiBackend.Core.Infrastructure.Environments;
using MonifiBackend.UserModule.Domain.Users;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MonifiBackend.UserModule.Infrastructure.Users
{
    public class JwtUtils : IJwtUtils
    {
        private readonly ApplicationSettings _appSettings;

        public JwtUtils(IOptions<ApplicationSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }

        public async Task<JwtSecurityToken> GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Id.ToString()),
                new Claim("id", user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("roles", user.Role.ToString())
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appSettings.Secret.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _appSettings.Secret.Issuer,
                audience: _appSettings.Secret.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_appSettings.Secret.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }

        public int? ValidateJwtToken(string token)
        {
            if (token == null)
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret.Key);
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

                // return user id from JWT token if validation successful
                return userId;
            }
            catch
            {
                // return null if validation fails
                return null;
            }
        }
    }
}
