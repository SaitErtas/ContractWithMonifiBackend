using MonifiBackend.Core.Domain.Base;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Utility
{
    public class AppRuleTests
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void NotNullOrEmpty_Should_ThrowException_When_ValueIsNullOrEmpty(string value)
        {
            var exceptionText = "Exception";

            var exception = Assert.Throws<SampleException>(() => AppRule.NotNullOrEmpty<SampleException>(value, exceptionText));

            Assert.Equal(exceptionText, exception.DisplayMessage);
        }
        [Fact]
        public void NotNegative_Should_ThrowException_When_ValueIsNegative()
        {
            var value = -1;
            var exceptionText = "Exception";

            var exception = Assert.Throws<SampleException>(() => AppRule.NotNegative<SampleException>(value, exceptionText));

            Assert.Equal(exceptionText, exception.DisplayMessage);
        }
        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        public void NotNegativeOrZero_Should_ThrowException_When_NotNegativeOrZero(int value)
        {
            var exceptionText = "Exception";

            var exception = Assert.Throws<SampleException>(() => AppRule.NotNegativeOrZero<SampleException>(value, exceptionText));

            Assert.Equal(exceptionText, exception.DisplayMessage);
        }
        [Fact]
        public void True_Should_ThrowException_When_ValueIsFalse()
        {
            var value = false;
            var exceptionText = "Exception";

            var exception = Assert.Throws<SampleException>(() => AppRule.True<SampleException>(value, exceptionText));

            Assert.Equal(exceptionText, exception.DisplayMessage);
        }
        [Fact]
        public void True_Should_Throw_Exception_When_ValueIsFalse()
        {
            var value = false;
            var exceptionText = "Exception";

            Assert.Throws<SampleException>(() => AppRule.True(value, new SampleException(exceptionText)));
        }
        [Fact]
        public void False_Should_ThrowException_When_ValueIsTrue()
        {
            var value = true;
            var exceptionText = "Exception";

            var exception = Assert.Throws<SampleException>(() => AppRule.False<SampleException>(value, exceptionText));

            Assert.Equal(exceptionText, exception.DisplayMessage);
        }
        [Fact]
        public void ExistsAndActive_Should_ThrowException_When_ValueNotActive()
        {
            var value = new Sample(1, "Hakan", BaseStatus.Passive);

            var exceptionText = "Exception";

            Assert.Throws<SampleException>(() => AppRule.ExistsAndActive(value, new SampleException(exceptionText)));
        }
        private class SampleException : BaseException
        {
            private string _displayMessage;
            public SampleException(string displayMessage) : base()
            {
                _displayMessage = displayMessage;
            }
            public override string ExceptionId => "5ec3d04d-8655-4b49-9cf4-6a2c26ddb170";
            public override string DisplayMessage => $"{_displayMessage}";
            public override string Message => $"{_displayMessage}";
            public override int Status => 500;
        }
        private class Sample : BaseDomain<int>
        {
            public Sample(int id, string name, BaseStatus status)
            {
                Id = id;
                Name = name;
                Status = status;
            }
            public string Name { get; private set; }
        }
    }
}
