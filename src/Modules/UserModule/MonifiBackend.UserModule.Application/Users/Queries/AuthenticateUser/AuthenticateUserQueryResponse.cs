using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Queries.AuthenticateUser;

public class AuthenticateUserQueryResponse
{
    public AuthenticateUserQueryResponse(User user)
    {
        Id = user.Id;
        Email = user.Email;
        Role = user.Role.ToString();
    }
    public int Id { get; set; }
    public string Email { get; set; }
    public string Role { get; set; }
}
