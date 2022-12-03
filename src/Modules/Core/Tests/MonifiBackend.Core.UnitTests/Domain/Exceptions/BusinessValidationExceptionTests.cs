using MonifiBackend.Core.Domain.Exceptions;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Exceptions
{
    public class BusinessValidationExceptionTests
    {
        [Fact]
        public void BusinessValidationException_Should_Be_Successful()
        {
            string otherDisplayMessage = "1 id bilgisi ile sistemde kayıtlı kulanıcı silinemedi!";
            string otherExcetionMessage = "User Id: 1";

            var exceptionStatus = 500;
            var exceptionId = "59caf220-9308-4a63-86d9-281f5bd88f64";
            var displayMessage = $"{otherDisplayMessage}";
            var message = $"Business Exception! {otherExcetionMessage}";
            var sample = new BusinessValidationException(otherDisplayMessage, otherExcetionMessage);

            Assert.Equal(sample.ExceptionId, exceptionId);
            Assert.Equal(sample.DisplayMessage, displayMessage);
            Assert.Equal(sample.Message, message);
            Assert.Equal(sample.Status, exceptionStatus);
        }
    }
}
