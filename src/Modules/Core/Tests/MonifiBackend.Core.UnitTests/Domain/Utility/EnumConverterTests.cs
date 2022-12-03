using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.UnitTests.Base;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Utility
{
    public class EnumConverterTests : TestBase
    {
        [Fact]
        public void ToInt_Should_Be_Successful()
        {
            var actual = 1;
            var expected = TestEnum.NONE.ToInt();

            Assert.Equal(expected, actual);
        }
        [Fact]
        public void ToEnum_Should_Be_Successful()
        {
            var actual = TestEnum.NONE;
            var expected = 1.ToEnum<TestEnum>();

            Assert.Equal(expected, actual);
        }
        private enum TestEnum
        {
            NONE = 1,
        }
    }
}
