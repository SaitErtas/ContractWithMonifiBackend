using MonifiBackend.Core.Domain.Exceptions;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Exceptions
{
    public class DomainExceptionTests
    {
        [Fact]
        public void BusinessValidationException_Should_Be_Successful()
        {
            string otherDisplayMessage = "1 id bilgisi ile sistemde kayıtlı kulanıcı silinemedi!";
            string otherExcetionMessage = "User Id: 1";

            var exceptionStatus = 500;
            var exceptionId = "dbd35e2d-dc2d-4568-b415-4dcd291562c1";
            var displayMessage = $"{otherDisplayMessage}";
            var message = $"Domain Exception! {otherExcetionMessage}";
            var sample = new DomainException(otherDisplayMessage, otherExcetionMessage);

            Assert.Equal(sample.ExceptionId, exceptionId);
            Assert.Equal(sample.DisplayMessage, displayMessage);
            Assert.Equal(sample.Message, message);
            Assert.Equal(sample.Status, exceptionStatus);
        }
    }
}
