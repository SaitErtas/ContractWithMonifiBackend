using MonifiBackend.Core.Domain.Base;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Base
{
    public class ReadOnlyBaseDomainTests
    {
        #region IsExist Int
        [Fact]
        public void IsExist_Should_Return_False_When_Deleted()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Deleted);
            var expected = sample.IsExist();
            Assert.NotNull(sample.CreatedAt);
            Assert.NotNull(sample.ModifiedAt);
            Assert.False(expected);
        }
        [Fact]
        public void IsExist_Should_Return_True()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.True(expected);
        }
        [Fact]
        public void IsExist_Should_Return_False_When_Example_Not_Valid_Id()
        {
            var sample = new Sample(0, "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.False(expected);
        }
        #endregion
        #region IsExist String
        [Fact]
        public void IsExist_Should_Return_False_When_Deleted_String()
        {
            var sample = new Sample2("1", "Hakan", BaseStatus.Deleted);
            var expected = sample.IsExist();
            Assert.False(expected);
        }
        [Fact]
        public void IsExist_Should_Return_True_String()
        {
            var sample = new Sample2("1", "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.True(expected);
        }
        [Fact]
        public void IsExist_Should_Return_False_When_Example_Not_Valid_Id_String()
        {
            var sample = new Sample2(null, "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.False(expected);
        }
        #endregion
        [Fact]
        public void IsActive_Should_Return_True()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Active);
            Assert.True(sample.IsActive());
        }
        [Fact]
        public void IsActive_Should_Return_False()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Passive);
            Assert.False(sample.IsActive());
        }
        [Fact]
        public void IsPassive_Should_Return_True()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Passive);
            Assert.True(sample.IsPassive());
        }
        [Fact]
        public void IsPassive_Should_Return_False()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Active);
            Assert.False(sample.IsPassive());
        }
        [Fact]
        public void IsDeleted_Should_Return_True()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Deleted);
            Assert.True(sample.IsDeleted());
        }
        [Fact]
        public void IsDeleted_Should_Return_False()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Active);
            Assert.False(sample.IsDeleted());
        }
        private class Sample : ReadOnlyBaseDomain<int>
        {
            public Sample(int id, string name, BaseStatus status)
            {
                Id = id;
                Name = name;
                Status = status;
            }
            public string Name { get; private set; }
        }
        private class Sample2 : ReadOnlyBaseDomain<string>
        {
            public Sample2(string id, string name, BaseStatus status)
            {
                Id = id;
                Name = name;
                Status = status;
            }
            public string Name { get; private set; }
        }
    }
}
