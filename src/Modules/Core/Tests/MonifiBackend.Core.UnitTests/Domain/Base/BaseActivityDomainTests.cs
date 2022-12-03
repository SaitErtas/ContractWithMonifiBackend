using MonifiBackend.Core.Domain.Base;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Base
{
    public class BaseActivityDomainTests
    {
        [Fact]
        public void SetCreatedAt_Should_Be_Successful()
        {
            var actual = new DateTime(2022, 04, 16);
            var sample = new Sample();

            sample.SetCreatedAt(actual);

            Assert.Equal(sample.CreatedAt, actual);
        }

        [Fact]
        public void SetModifiedAt_Should_Be_Successful()
        {
            var actual = new DateTime(2022, 04, 16);
            var sample = new Sample();

            sample.SetModifiedAt(actual);

            Assert.Equal(sample.ModifiedAt, actual);
        }

        private class Sample : BaseActivityDomain<int>
        {
            public string Name { get; set; }
        }
    }
}
