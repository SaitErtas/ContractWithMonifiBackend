using MonifiBackend.Core.Domain.Abstractions;
using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.UserModule.Domain.Localizations;
using MonifiBackend.UserModule.Domain.Users.Notifications;
using MonifiBackend.UserModule.Domain.Users.Phones;
using MonifiBackend.UserModule.Domain.Wallets;

namespace MonifiBackend.UserModule.Domain.Users
{
    public sealed class User : BaseActivityDomain<int>, IAggregateRoot
    {
        public string Username { get; private set; }
        public string FullName { get; private set; }
        public string Email { get; private set; }
        public string Avatar { get; private set; }

        public Country Country { get; private set; } = new();
        public Language Language { get; private set; } = new();

        public string Password { get; private set; }
        public string ConfirmationCode { get; private set; }
        public string ResetPasswordCode { get; private set; }
        public string ReferanceCode { get; private set; }
        public int ReferanceUser { get; private set; }
        public bool Terms { get; private set; }
        public Role Role { get; private set; }
        public string Fa2Code { get; private set; }

        public Wallet Wallet { get; private set; }

        private List<UserPhone> _phones = new();
        public IReadOnlyCollection<UserPhone> Phones => _phones.AsReadOnly();

        private List<UserIP> _userIPs = new();
        public IReadOnlyCollection<UserIP> UserIPs => _userIPs.AsReadOnly();

        private List<UserNotification> _notifications = new();
        public IReadOnlyCollection<UserNotification> Notifications => _notifications.AsReadOnly();
        public void AddNotification(string message, string customerName, decimal price)
        {
            var notification = UserNotification.CreateNew(message, customerName, price);
            _notifications.Add(notification);
        }
        public void AddUserIP(string ipAddress, string requestName)
        {
            var userIP = UserIP.CreateNew(ipAddress, requestName);
            _userIPs.Add(userIP);
        }
        public void SetTerms(bool terms)
        {
            Terms = terms;
        }
        public void SetUsername(string username)
        {
            Username = username;
        }
        public void SetFullName(string fullName)
        {
            FullName = fullName;
        }
        public void SetFa2Code(string fa2Code)
        {
            Fa2Code = fa2Code;
        }
        public void SetCountry(Country country)
        {
            Country = country;
        }
        public void SetLanguage(Language language)
        {
            Language = language;
        }
        public void SetWallet(Wallet wallet)
        {
            Wallet = wallet;
        }
        public void SetEmail(string email)
        {
            AppRule.NotNullOrEmpty<DomainException>(email, "Email Cannot Be Null Or Empty");
            Email = email;
        }
        public void SetResetPasswordCode(string resetPasswordCode)
        {
            ResetPasswordCode = resetPasswordCode;
        }

        public void SetPassword(string password)
        {
            AppRule.NotNullOrEmpty<DomainException>(password, "Password Cannot Be Null Or Empty");
            Password = password;
        }
        public void SetRole(Role role) => Role = role;

        #region Phone
        public bool IsPhoneExists(string number) => _phones.Any(x => x.Number == number);

        public void AddPhone(string number)
        {
            AppRule.False<DomainException>(IsPhoneExists(number), "Phone Already Exists", $"Phone Already Exists. UserId: {Id}, Number: {number}");
            var phone = UserPhone.CreateNew(number);
            _phones.Add(phone);
        }

        public void DeletePhone(string number)
        {
            AppRule.True<DomainException>(IsPhoneExists(number), "Phone Not Exists", $"Phone Not Exists.  UserId: {Id}, Number: {number}");
            var phone = _phones.FirstOrDefault(x => x.Number == number);
            phone.MarkAsDeleted();
        }
        #endregion

        public static User Default() => new();

        public static User CreateNew(
            string email,
            string password,
            bool terms,
            int referanceUser,
            string referanceCode,
            string confirmationCode,
            string fa2Code,
            Language language,
            Country country,
            Wallet wallet,
            Role role,
            BaseStatus status)
        {
            AppRule.NotNullOrEmpty<DomainException>(email, "Email Cannot Be Null Or Empty", $"Email Cannot Be Null Or Empty. Email: {email}");
            AppRule.NotNullOrEmpty<DomainException>(password, "Password Cannot Be Null Or Empty", $"Password Cannot Be Null Or Empty. Password: {password}");
            AppRule.NotNegativeOrZero<DomainException>(referanceUser, "ReferanceUser Cannot Be Null Or Empty", $"ReferanceUser Cannot Be Null Or Empty. ReferanceUser: {referanceUser}");

            return new User()
            {
                Email = email,
                Password = password,
                Terms = terms,
                Status = status,
                Role = role,
                ResetPasswordCode = string.Empty,
                ReferanceCode = referanceCode,
                ReferanceUser = referanceUser,
                ConfirmationCode = confirmationCode,
                Username = string.Empty,
                FullName = string.Empty,
                Wallet = wallet,
                Language = language,
                Country = country,
                Fa2Code = fa2Code,
                Avatar = "/images/avatars/1.png"
            };
        }
        public static User Map(
            int id,
            BaseStatus status,
            string email,
            string password,
            string userName,
            bool terms,
            string resetPassword,
            int referanceUser,
            string referanceCode,
            string confirmationCode,
            string fullName,
            string avatar,
            string fa2Code,
            Language language,
            Country country,
            Wallet wallet,
            DateTime createdAt,
            DateTime modifiedAt,
            Role role,
            List<UserPhone> phones,
            List<UserNotification> notifications,
            List<UserIP> userIPs)
        {
            return new User()
            {
                Id = id,
                Status = status,
                Email = email,
                Password = password,
                Terms = terms,
                CreatedAt = createdAt,
                ModifiedAt = modifiedAt,
                Role = role,
                ResetPasswordCode = resetPassword,
                ReferanceUser = referanceUser,
                ReferanceCode = referanceCode,
                ConfirmationCode = confirmationCode,
                _phones = phones,
                _notifications = notifications,
                Username = userName,
                Fa2Code = fa2Code,
                Country = country,
                Language = language,
                Wallet = wallet,
                FullName = fullName,
                _userIPs = userIPs,
                Avatar = avatar,
            };
        }

    }
}
