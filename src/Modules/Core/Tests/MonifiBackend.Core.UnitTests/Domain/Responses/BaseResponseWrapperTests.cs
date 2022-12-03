using MonifiBackend.Core.Domain.Responses;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Responses
{
    public class BaseResponseWrapperTests
    {
        [Fact]
        public void BaseResponseWrapper_Should_Be_Successful()
        {
            var statusCode = 200;
            var sample = new BaseResponseWrapper(statusCode);

            Assert.Equal(sample.StatusCode, statusCode);
        }
        [Fact]
        public void BaseResponseWrapper_Should_Be_Successful_Errors()
        {
            var statusCode = 401;
            var errorCode = "ABC-1";
            var errors = new string[] { "ABC-101", "ABC-102" };
            var sample = new BaseResponseWrapper(statusCode, errorCode, errors);

            Assert.Equal(sample.StatusCode, statusCode);
            Assert.Equal(sample.ErrorCode, errorCode);
            Assert.Equal(sample.Errors, errors);
        }
        [Fact]
        public void BaseResponseWrapper_Should_Be_Successful_Error()
        {
            var statusCode = 401;
            var errorCode = "ABC-1";
            var errors = "ABC-101";
            var sample = new BaseResponseWrapper(statusCode, errorCode, errors);

            Assert.Equal(sample.StatusCode, statusCode);
            Assert.Equal(sample.ErrorCode, errorCode);
            Assert.Equal(sample.Errors.FirstOrDefault(), errors);
        }
    }
}
