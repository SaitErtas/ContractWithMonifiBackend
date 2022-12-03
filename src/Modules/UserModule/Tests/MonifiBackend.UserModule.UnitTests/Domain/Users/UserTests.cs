namespace MonifiBackend.UserModule.UnitTests.Domain.Users
{
    public class UserTests
    {
        //private readonly User _user;

        //#region Constructor
        //public UserTests()
        //{

        //    var phones = new List<UserPhone>()
        //    {
        //        UserPhone.Map(
        //            id : 1,
        //            status : BaseStatus.Active,
        //            number: "1234567890",
        //            phoneType: PhoneType.Mobile,
        //            createdAt: new DateTime(2022,04,16),
        //            modifiedAt: new DateTime(2022,04,17))
        //    };

        //    _user = User.Map(
        //        id: 1,
        //        status: BaseStatus.Active,
        //        email: "hakan-guzel@outlook.com",
        //        password: "123456",
        //        userName: "Hakan",
        //        terms: true,
        //        resetPassword: string.Empty,
        //        createdAt: DateTime.Now,
        //        modifiedAt: DateTime.Now,
        //        role: Role.Administrator,
        //        phones: phones
        //        );
        //}
        //#endregion

        //#region CreateNew Method Tests
        //[Theory]
        //[InlineData(null)]
        //[InlineData("")]
        //public void CreateNew_Should_ThrowException_When_UserNameIsNullOrEmpty(string userName)
        //{
        //    var exception = Assert.Throws<DomainException>(() =>
        //        User.CreateNew(
        //            email: "hakan-guzel@outlook.com",
        //            password: "123456",
        //            userName: userName,
        //            terms: true,
        //            role: Role.Administrator,
        //            status: BaseStatus.Active));

        //    Assert.IsType<DomainException>(exception);
        //}

        //[Fact]
        //public void CreateNew_Should_Be_Successful()
        //{
        //    var userName = "Hakan";
        //    var companyName = "Farmazon";
        //    var user = User.CreateNew(
        //            email: "hakan-guzel@outlook.com",
        //            password: "123456",
        //            userName: userName,
        //            terms: true,
        //            role: Role.Administrator,
        //            status: BaseStatus.Active);

        //    Assert.True(user.Status == BaseStatus.Active);
        //    Assert.True(user.UserName == userName);
        //}
        //#endregion

        //#region Map Method Tests

        //[Fact]
        //public void Map_Should_Be_Successful()
        //{
        //    var id = 1;
        //    var status = BaseStatus.Active;
        //    var dateTime = DateTime.Now;
        //    var userName = "Hakan";
        //    var companyName = "Farmazon";
        //    var phones = new List<UserPhone>();

        //    var user = User.Map(
        //        id: id,
        //        status: status,
        //        email: "hakan-guzel@outlook.com",
        //        password: "123456",
        //        userName: userName,
        //        terms: true,
        //        resetPassword: string.Empty,
        //        createdAt: dateTime,
        //        modifiedAt: dateTime,
        //        role: Role.Administrator,
        //        phones: phones
        //        );

        //    Assert.Equal(id, user.Id);
        //    Assert.Equal(status, user.Status);
        //    Assert.Equal(userName, user.UserName);
        //    Assert.Equal(dateTime, user.CreatedAt);
        //    Assert.Equal(dateTime, user.ModifiedAt);
        //    Assert.Equal(phones.Count, user.Phones.Count);
        //}
        //#endregion

        //#region Default Method Tests
        //[Fact]
        //public void Default_Should_Be_Successful()
        //{
        //    var user = User.Default();
        //    Assert.False(user.IsExist());
        //}
        //#endregion

        //#region Is Phone Exists Tests
        //[Fact]
        //public void IsPhoneExists_Should_Return_True()
        //{
        //    var number = "55555555";
        //    var phoneType = PhoneType.Mobile;
        //    _user.AddPhone(number, phoneType);
        //    var result = _user.IsPhoneExists(number, phoneType);
        //    Assert.True(result);
        //}

        //[Fact]
        //public void IsPhoneExists_Should_Return_False()
        //{
        //    var number = "55555555";
        //    var phoneType = PhoneType.Mobile;
        //    _user.AddPhone(number, phoneType);
        //    var result = _user.IsPhoneExists(number, phoneType);
        //    Assert.True(result);
        //}
        //#endregion

        //#region Add Contact Tests
        //[Theory]
        //[InlineData("5555123456", PhoneType.Mobile)]
        //[InlineData("2122121221", PhoneType.Home)]
        //[InlineData("2122121221", PhoneType.Work)]
        //public void AddContact_Should_Throw_Exception_When_Phone_Already_Exists(string number, PhoneType phoneType)
        //{
        //    _user.AddPhone(number, phoneType);

        //    Assert.Throws<DomainException>(() => _user.AddPhone(number, phoneType));
        //}

        //[Theory]
        //[InlineData("5555123456", PhoneType.Mobile)]
        //[InlineData("2122121221", PhoneType.Home)]
        //[InlineData("2122121221", PhoneType.Work)]
        //public void AddContact_Should_Be_Successful(string number, PhoneType phoneType)
        //{
        //    _user.AddPhone(number, phoneType);
        //    Assert.Contains(_user.Phones, phone => phone.Number == number && phone.PhoneType == phoneType && phone.IsActive());
        //}
        //#endregion

        //#region Delete Contact Tests

        //[Fact]
        //public void DeleteContact_Should_Throw_Exception_When_Contact_Not_Found()
        //{
        //    var number = "5555555555";
        //    var phoneType = PhoneType.Mobile;
        //    Assert.Throws<DomainException>(() => _user.DeletePhone(number, phoneType));
        //}

        //[Fact]
        //public void DeleteContact_Should_Be_Successful()
        //{
        //    var number = "5555555555";
        //    var phoneType = PhoneType.Mobile;
        //    _user.AddPhone(number, phoneType);
        //    _user.DeletePhone(number, phoneType);
        //    Assert.Contains(_user.Phones, phone => phone.IsDeleted());
        //}
        //#endregion

    }
}
