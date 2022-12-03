namespace MonifiBackend.UserModule.Domain.Users
{
    public enum Role
    {
        Administrator = 1,
        Owner = 2,
        User = 3
    }
    public class RoleStrings
    {
        public const string ADMINISTRATOR = "admin";
        public const string OWNER = "owner";
        public const string USER = "user";
    }
    public static class RoleExtensions
    {
        public static string ToRole(this Role status)
        {
            return status switch
            {
                Role.Administrator => RoleStrings.ADMINISTRATOR,
                Role.Owner => RoleStrings.OWNER,
                Role.User => RoleStrings.USER,
                _ => throw new NotImplementedException()
            };
        }
    }
}
