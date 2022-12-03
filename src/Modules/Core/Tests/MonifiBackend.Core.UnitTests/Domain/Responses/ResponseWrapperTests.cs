using MonifiBackend.Core.Domain.Responses;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Responses
{
    public class ResponseWrapperTests
    {
        [Fact]
        public void ResponseWrapper_Should_Be_Successful_Empty()
        {
            var statusCode = 200;

            var sample = new ResponseWrapper<string>();

            Assert.Equal(sample.StatusCode, statusCode);
        }
        [Fact]
        public void ResponseWrapper_Should_Be_Successful_Result()
        {
            var statusCode = 200;
            var result = "Hello World";

            var sample = new ResponseWrapper<string>(result);

            Assert.Equal(sample.StatusCode, statusCode);
            Assert.Equal(sample.Result, result);
        }
        [Fact]
        public void ResponseWrapper_Should_Be_Successful_Error()
        {
            var statusCode = 200;
            var errorCode = "ABC-1";
            var errors = new string[] { "ABC-101", "ABC-102" };

            var sample = new ResponseWrapper<string>(statusCode, errorCode, errors);

            Assert.Equal(sample.StatusCode, statusCode);
            Assert.Equal(sample.ErrorCode, errorCode);
            Assert.Equal(sample.Errors, errors);
        }
        [Fact]
        public void ResponseWrapper_Should_Be_Successful_Errors()
        {
            var statusCode = 200;
            var errorCode = "ABC-1";
            var errorMessage = "ABC-101";

            var sample = new ResponseWrapper<string>(statusCode, errorCode, errorMessage);

            Assert.Equal(sample.StatusCode, statusCode);
            Assert.Equal(sample.ErrorCode, errorCode);
            Assert.Equal(sample.Errors.FirstOrDefault(), errorMessage);
        }
    }
}
