using FluentValidation.Results;
using Microsoft.AspNetCore.Http;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Logging;
using MonifiBackend.Core.Infrastructure.Middlewares;
using Moq;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Infrastructure.Middlewares
{
    public class ExceptionMiddlewareTests
    {
        private readonly Mock<ILogPort> _mockLogPort;
        public ExceptionMiddlewareTests()
        {
            _mockLogPort = new Mock<ILogPort>();
        }
        [Fact]
        public async Task ExceptionMiddleware_BaseException()
        {
            _mockLogPort.Setup(q => q.LogError(It.IsAny<string>(), It.IsAny<Exception>()));
            //arrange
            var expectedContent = "{\"Result\":null,\"Success\":false,\"StatusCode\":500,\"ErrorCode\":\"0e76a36a-07f8-477d-930c-0566d542f88c\",\"Errors\":[\"1 User Not Deleted!\"]}";
            RequestDelegate mockNextMiddleware = (HttpContext) =>
            {
                return Task.FromException(new SampleException(1));
            };

            var httpContext = new DefaultHttpContext();
            httpContext.Response.Body = new MemoryStream();

            var exceptionHandlingMiddleware = new ExceptionMiddleware(mockNextMiddleware, _mockLogPort.Object);

            //act
            await exceptionHandlingMiddleware.InvokeAsync(httpContext);

            httpContext.Response.Body.Position = 0;
            var bodyContent = "";
            using (var sr = new StreamReader(httpContext.Response.Body))
                bodyContent = sr.ReadToEnd();

            Assert.Equal(expectedContent, bodyContent);
        }
        [Fact]
        public async Task ExceptionMiddleware_ValidationException()
        {
            var validationFailure = new ValidationFailure[] { new ValidationFailure("a", "b"), new ValidationFailure("c", "d") };
            var validationException = new FluentValidation.ValidationException("Test", validationFailure);
            _mockLogPort.Setup(q => q.LogError(It.IsAny<string>(), It.IsAny<Exception>()));
            //arrange
            var expectedContent = "{\"Result\":null,\"Success\":false,\"StatusCode\":400,\"ErrorCode\":\"VAL-101\",\"Errors\":[\"b\",\"d\"]}";
            RequestDelegate mockNextMiddleware = (HttpContext) =>
            {

                return Task.FromException(validationException);
            };

            var httpContext = new DefaultHttpContext();
            httpContext.Response.Body = new MemoryStream();

            var exceptionHandlingMiddleware = new ExceptionMiddleware(mockNextMiddleware, _mockLogPort.Object);

            //act
            await exceptionHandlingMiddleware.InvokeAsync(httpContext);

            httpContext.Response.Body.Position = 0;
            var bodyContent = "";
            using (var sr = new StreamReader(httpContext.Response.Body))
                bodyContent = sr.ReadToEnd();

            Assert.Equal(expectedContent, bodyContent);
        }
        [Fact]
        public async Task ExceptionMiddleware_ArgumentNullException()
        {
            _mockLogPort.Setup(q => q.LogError(It.IsAny<string>(), It.IsAny<Exception>()));
            //arrange
            var expectedContent = "{\"Result\":null,\"Success\":false,\"StatusCode\":500,\"ErrorCode\":\"SYS-101\",\"Errors\":[\"Value cannot be null.\"]}";
            RequestDelegate mockNextMiddleware = (HttpContext) =>
            {
                return Task.FromException(new ArgumentNullException());
            };

            var httpContext = new DefaultHttpContext();
            httpContext.Response.Body = new MemoryStream();

            var exceptionHandlingMiddleware = new ExceptionMiddleware(mockNextMiddleware, _mockLogPort.Object);

            //act
            await exceptionHandlingMiddleware.InvokeAsync(httpContext);

            httpContext.Response.Body.Position = 0;
            var bodyContent = "";
            using (var sr = new StreamReader(httpContext.Response.Body))
                bodyContent = sr.ReadToEnd();

            Assert.Equal(expectedContent, bodyContent);
        }
        private class SampleException : BaseException
        {
            private int _userId;
            public SampleException(int userId)
            {
                _userId = userId;
            }

            public override int Status => 500;
            public override string ExceptionId => "0e76a36a-07f8-477d-930c-0566d542f88c";
            public override string DisplayMessage => $"{_userId} User Not Deleted!";
            public override string Message => $"User Not Deleted! User Id: {_userId}";
        }
    }
}
