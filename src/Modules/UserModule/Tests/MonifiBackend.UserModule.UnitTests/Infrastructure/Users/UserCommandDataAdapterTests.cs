using MonifiBackend.UserModule.UnitTests.Base;

namespace MonifiBackend.UserModule.UnitTests.Infrastructure.Users
{
    public class UserCommandDataAdapterTests : TestBase
    {
        //private readonly UserCommandDataAdapter _dataAdapter;
        //private readonly Mock<IMonifiBackendDbContext> _mockAppDbContext;
        //public UserCommandDataAdapterTests()
        //{
        //    _mockAppDbContext = new Mock<IMonifiBackendDbContext>();
        //    _dataAdapter = new UserCommandDataAdapter(_mockAppDbContext.Object);
        //}
        //[Fact]
        //public async Task CreateAsync_Should_Return_Response_When_Success()
        //{
        //    var userId = 1;
        //    var user = GetGeneratedActiveUser();
        //    _mockAppDbContext.Setup(q => q.Users.AddAsync(It.IsAny<UserEntity>(), CancellationToken.None));

        //    _mockAppDbContext.Setup(q => q.SaveChangesAsync(CancellationToken.None))
        //        .ReturnsAsync(userId);

        //    var actual = await _dataAdapter.CreateAsync(user);
        //    Assert.Equal(userId, actual);
        //}
        //[Fact]
        //public async Task CreateAsync_Throws_Fail_When_User_Not_Created()
        //{
        //    var userId = 0;
        //    var user = GetGeneratedActiveUser();
        //    _mockAppDbContext.Setup(q => q.Users.AddAsync(It.IsAny<UserEntity>(), CancellationToken.None));

        //    _mockAppDbContext.Setup(q => q.SaveChangesAsync(CancellationToken.None))
        //        .ReturnsAsync(userId);

        //    var actual = await _dataAdapter.CreateAsync(user);
        //    Assert.Equal(userId, actual);
        //}

        //[Fact]
        //public async Task SaveAsync_Should_Return_Response_When_Success()
        //{
        //    var userId = 1;
        //    var user = GetGeneratedActiveUser();
        //    _mockAppDbContext.Setup(q => q.Users.Update(It.IsAny<UserEntity>()));

        //    _mockAppDbContext.Setup(q => q.SaveChangesAsync(CancellationToken.None))
        //        .ReturnsAsync(userId);

        //    var actual = await _dataAdapter.SaveAsync(user);
        //    Assert.True(actual);
        //}
        //[Fact]
        //public async Task SaveAsync_Throws_Fail_When_User_Not_Saved()
        //{
        //    var userId = 0;
        //    var user = GetGeneratedActiveUser();
        //    _mockAppDbContext.Setup(q => q.Users.Update(It.IsAny<UserEntity>()));

        //    _mockAppDbContext.Setup(q => q.SaveChangesAsync(CancellationToken.None))
        //        .ReturnsAsync(userId);

        //    var actual = await _dataAdapter.SaveAsync(user);
        //    Assert.False(actual);
        //}
    }
}
