using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Data.Infrastructure.Entities;
using MonifiBackend.UserModule.Domain.Users.Phones;
using MonifiBackend.UserModule.Infrastructure.Extensions.Mappers;
using Xunit;

namespace MonifiBackend.UserModule.UnitTests.Infrastructure.Extensions.Mappers
{
    public class UserPhoneTests
    {
        [Fact]
        public void Map_Should_Return_ValidEntityObject()
        {
            var entity =
                new UserPhoneEntity
                {
                    Number = "5555555",
                    Status = BaseStatus.Active.ToInt(),
                    UserId = 1,
                };


            var domain = entity.Map();

            Assert.Equal(domain.Id, entity.Id);
            Assert.Equal(domain.Number, entity.Number);
            Assert.Equal(domain.Status.ToInt(), entity.Status);
            Assert.Equal(domain.CreatedAt, entity.CreatedAt);
            Assert.Equal(domain.ModifiedAt, entity.ModifiedAt);
            Assert.Equal(domain.Status.ToInt(), entity.Status);
        }
        [Fact]
        public void Map_Should_Return_ValidDomainObject()
        {
            var domain = UserPhone.CreateNew("5555555555");
            var entity = domain.Map();

            Assert.Equal(domain.Number, entity.Number);
            Assert.Equal(domain.CreatedAt, entity.CreatedAt);
            Assert.Equal(domain.ModifiedAt, entity.ModifiedAt);
            Assert.Equal(domain.Status.ToInt(), entity.Status);
        }
    }
}
