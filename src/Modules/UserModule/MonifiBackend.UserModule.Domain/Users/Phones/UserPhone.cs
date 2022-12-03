using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;

namespace MonifiBackend.UserModule.Domain.Users.Phones
{
    public sealed class UserPhone : BaseActivityDomain<int>
    {
        private UserPhone() { }
        public string Number { get; private set; }
        public static UserPhone CreateNew(string number)
        {
            AppRule.NotNullOrEmpty<DomainException>(number, "Phone number not null or empty", $"Phone number not null or empty. Number: {number}");

            return new UserPhone()
            {
                Number = number
            };
        }
        public void SetPhone(string number)
        {
            Number = number;
        }
        public static UserPhone Default() => new();

        public static UserPhone Map(
            int id,
            BaseStatus status,
            string number,
            DateTime createdAt,
            DateTime modifiedAt)
        {
            return new UserPhone()
            {
                Id = id,
                Status = status,
                Number = number,
                CreatedAt = createdAt,
                ModifiedAt = modifiedAt
            };
        }
    }
}
