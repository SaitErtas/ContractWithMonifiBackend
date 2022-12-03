using MonifiBackend.UserModule.UnitTests.Base;

namespace MonifiBackend.UserModule.UnitTests.Application.Commands
{
    public class ChangedPasswordCommandTests : TestBase
    {
        //    private readonly ChangedPasswordCommandHandler _handler;

        //    private readonly Mock<IUserQueryDataPort> _mockUserQueryDataPort;
        //    private readonly Mock<IUserCommandDataPort> _mockUserCommandDataPort;
        //    public ChangedPasswordCommandTests()
        //    {
        //        _mockUserQueryDataPort = new Mock<IUserQueryDataPort>();
        //        _mockUserCommandDataPort = new Mock<IUserCommandDataPort>();
        //        _handler = new ChangedPasswordCommandHandler(_mockUserQueryDataPort.Object, _mockUserCommandDataPort.Object);
        //    }
        //    public static IEnumerable<object[]> ChangedPasswordCommand()
        //    {
        //        yield return new object[] {
        //            new ChangedPasswordCommand
        //            {
        //                Email = "hakan-guzel@outlook.com",
        //                NewPassword = "123456",
        //                ResetPasswordCode = "ASD123ASD"
        //            }
        //        };
        //    }
        //    [Theory]
        //    [MemberData(nameof(ChangedPasswordCommand))]
        //    public async Task ChangedPasswordCommandHandler_Throws_Exception_When_User_Not_Updated_Exception(ChangedPasswordCommand command)
        //    {
        //        var user = GetGeneratedActiveUser();
        //        user.SetResetPasswordCode("ASD123ASD");
        //        var status = false;

        //        _mockUserQueryDataPort.Setup(q => q.GetEmailAsync(command.Email))
        //            .ReturnsAsync(user);
        //        _mockUserCommandDataPort.Setup(q => q.SaveAsync(It.IsAny<User>()))
        //            .ReturnsAsync(status);

        //        await Assert.ThrowsAsync<BusinessValidationException>(async () => await _handler.Handle(command, cancellationToken: CancellationToken.None));
        //    }
        //    [Theory]
        //    [MemberData(nameof(ChangedPasswordCommand))]
        //    public async Task ChangedPasswordCommandHandler_Throws_Exception_When_User_Not_Found_Exception(ChangedPasswordCommand command)
        //    {
        //        var user = GetGeneratedDeletedUser();
        //        user.SetResetPasswordCode("ASD123ASD");

        //        _mockUserQueryDataPort.Setup(q => q.GetEmailAsync(command.Email))
        //            .ReturnsAsync(user);

        //        await Assert.ThrowsAsync<BusinessValidationException>(async () => await _handler.Handle(command, cancellationToken: CancellationToken.None));
        //    }
        //    [Theory]
        //    [MemberData(nameof(ChangedPasswordCommand))]
        //    public async Task ChangedPasswordCommandHandler_Throws_Exception_When_ResetPasswordCode_Not_Mach_Exception(ChangedPasswordCommand command)
        //    {
        //        var user = GetGeneratedDeletedUser();

        //        _mockUserQueryDataPort.Setup(q => q.GetEmailAsync(command.Email))
        //            .ReturnsAsync(user);

        //        await Assert.ThrowsAsync<BusinessValidationException>(async () => await _handler.Handle(command, cancellationToken: CancellationToken.None));
        //    }
        //    [Theory]
        //    [MemberData(nameof(ChangedPasswordCommand))]
        //    public async Task ChangedPasswordCommandHandler_Should_ReturnResponse_When_Success(ChangedPasswordCommand command)
        //    {
        //        var user = GetGeneratedActiveUser();
        //        user.SetResetPasswordCode("ASD123ASD");
        //        var status = true;

        //        _mockUserQueryDataPort.Setup(q => q.GetEmailAsync(command.Email))
        //            .ReturnsAsync(user);
        //        _mockUserCommandDataPort.Setup(q => q.SaveAsync(It.IsAny<User>()))
        //            .ReturnsAsync(status);

        //        var response = await _handler.Handle(command, cancellationToken: CancellationToken.None);
        //        Assert.IsType<ChangedPasswordCommandResponse>(response);
        //    }
    }
}
