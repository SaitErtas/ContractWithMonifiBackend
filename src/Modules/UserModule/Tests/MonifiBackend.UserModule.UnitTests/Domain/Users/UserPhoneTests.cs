namespace MonifiBackend.UserModule.UnitTests.Domain.Users
{
    public class UserPhoneTests
    {
        //private readonly UserPhone _userContact;

        //#region Constructor
        //public UserPhoneTests()
        //{
        //    _userContact = UserPhone.Map(
        //            id: 1,
        //            status: BaseStatus.Active,
        //            number: "1234567890",
        //            phoneType: PhoneType.Mobile,
        //            createdAt: DateTime.Now,
        //            modifiedAt: DateTime.Now);
        //}
        //#endregion

        //#region CreateNew Method Tests
        //[Theory]
        //[InlineData(null)]
        //[InlineData("")]
        //public void CreateNew_Should_ThrowException_When_ContentIsNullOrEmpty(string number)
        //{
        //    Assert.Throws<DomainException>(() =>
        //        UserPhone.CreateNew(
        //            number: number,
        //            phoneType: PhoneType.Mobile));
        //}
        //[Fact]
        //public void CreateNew_Should_Be_Successful()
        //{
        //    var number = "1234567890";
        //    var phoneType = PhoneType.Mobile;
        //    var contact = UserPhone.CreateNew(
        //            number: number,
        //            phoneType: phoneType);

        //    Assert.True(contact.Status == BaseStatus.Active);
        //    Assert.True(contact.Number == number);
        //    Assert.True(contact.PhoneType == phoneType);
        //}
        //#endregion

        //#region Map Method Tests

        //[Fact]
        //public void Map_Should_Be_Successful()
        //{
        //    var id = 1;
        //    var status = BaseStatus.Active;
        //    var dateTime = DateTime.Now;
        //    var number = "1234567890";
        //    var phoneType = PhoneType.Mobile;

        //    var contact = UserPhone.Map(
        //        id: id,
        //        status: status,
        //        number: number,
        //        phoneType: phoneType,
        //        createdAt: dateTime,
        //        modifiedAt: dateTime
        //        );

        //    Assert.Equal(id, contact.Id);
        //    Assert.Equal(status, contact.Status);
        //    Assert.Equal(number, contact.Number);
        //    Assert.Equal(phoneType, contact.PhoneType);
        //    Assert.Equal(dateTime, contact.CreatedAt);
        //    Assert.Equal(dateTime, contact.ModifiedAt);
        //}
        //#endregion
    }
}
