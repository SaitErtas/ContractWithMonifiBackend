using MonifiBackend.UserModule.Domain.Users;

namespace MonifiBackend.UserModule.Application.Users.Commands.ConfirmUser;

public class ConfirmUserCommandResponse
{
    public ConfirmUserCommandResponse(User user, string accessToken)
    {
        Id = user.Id;
        Email = user.Email;
        Role = user.Role.ToString();
        AccessToken = accessToken;
    }
    public int Id { get; set; }
    public string Email { get; set; }
    public string Role { get; set; }
    public string AccessToken { get; set; }
}
