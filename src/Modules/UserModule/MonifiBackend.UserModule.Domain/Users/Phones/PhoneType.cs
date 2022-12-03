namespace MonifiBackend.UserModule.Domain.Users.Phones
{
    public enum PhoneType
    {
        Mobile = 1,
        Home = 2,
        Work = 3
    }
    public class PhoneTypeStrings
    {
        public const string MOBILE = "mobile";
        public const string HOME = "home";
        public const string WORK = "work";
    }
    public static class PhoneTypeExtensions
    {
        public static PhoneType ToPhoneType(this string status)
        {
            return status switch
            {
                PhoneTypeStrings.MOBILE => PhoneType.Mobile,
                PhoneTypeStrings.HOME => PhoneType.Home,
                PhoneTypeStrings.WORK => PhoneType.Work,
                _ => throw new NotImplementedException()
            };
        }
        public static string ToPhoneType(this PhoneType status)
        {
            return status switch
            {
                PhoneType.Mobile => PhoneTypeStrings.MOBILE,
                PhoneType.Home => PhoneTypeStrings.HOME,
                PhoneType.Work => PhoneTypeStrings.WORK,
                _ => throw new NotImplementedException()
            };
        }
    }
}
