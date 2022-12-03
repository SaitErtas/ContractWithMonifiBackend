using MonifiBackend.Core.Domain.Base;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Base
{
    public class BaseDomainTests
    {
        private readonly Sample _sample;
        public BaseDomainTests()
        {
            _sample = new Sample(1, "Hakan", BaseStatus.Active);
        }
        [Fact]
        public void MarkAsActive_Should_Be_Successful()
        {
            var status = BaseStatus.Active;

            _sample.MarkAsActive();

            Assert.Equal(_sample.Status, status);
        }

        [Fact]
        public void MarkAsPassive_Should_Be_Successful()
        {
            var status = BaseStatus.Passive;

            _sample.MarkAsPassive();

            Assert.Equal(_sample.Status, status);
        }

        [Fact]
        public void MarkAsDeleted_Should_Be_Successful()
        {
            var status = BaseStatus.Deleted;

            _sample.MarkAsDeleted();

            Assert.Equal(_sample.Status, status);
        }

        [Theory]
        [InlineData(BaseStatus.Active)]
        [InlineData(BaseStatus.Passive)]
        [InlineData(BaseStatus.Deleted)]
        public void SetStatus_Should_Be_Successful(BaseStatus status)
        {
            _sample.SetStatus(status);

            Assert.Equal(_sample.Status, status);
        }

        #region IsExist Ing
        [Fact]
        public void IsExist_Should_Return_True()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.True(expected);
        }
        [Fact]
        public void IsExist_Should_Return_False_When_Deleted()
        {
            var sample = new Sample(1, "Hakan", BaseStatus.Deleted);
            sample.MarkAsDeleted();
            var expected = sample.IsExist();
            Assert.False(expected);
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
        public void IsExist_Should_Return_True_String()
        {
            var sample = new Sample2("1", "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.True(expected);
        }
        [Fact]
        public void IsExist_Should_Return_False_When_Deleted_String()
        {
            var sample = new Sample2("1", "Hakan", BaseStatus.Deleted);
            sample.MarkAsDeleted();
            var expected = sample.IsExist();
            Assert.False(expected);
        }
        [Fact]
        public void IsExist_Should_Return_False_When_Example_Not_Valid_Id_String()
        {
            var sample = new Sample2(null, "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.False(expected);
        }
        #endregion
        #region IsExist String
        [Fact]
        public void IsExist_Should_Return_True_Object()
        {
            var sample = new Sample3(Guid.NewGuid(), "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.True(expected);
        }
        [Fact]
        public void IsExist_Should_Return_False_When_Deleted_Object()
        {
            var sample = new Sample3(Guid.NewGuid(), "Hakan", BaseStatus.Deleted);
            sample.MarkAsDeleted();
            var expected = sample.IsExist();
            Assert.False(expected);
        }
        [Fact]
        public void IsExist_Should_Return_False_When_Example_Not_Valid_Id_Object()
        {
            var sample = new Sample3(null, "Hakan", BaseStatus.Active);
            var expected = sample.IsExist();
            Assert.False(expected);
        }
        #endregion
        [Fact]
        public void IsActive_Should_Return_True()
        {
            _sample.MarkAsActive();
            Assert.True(_sample.IsActive());
        }
        [Fact]
        public void IsActive_Should_Return_False()
        {
            _sample.MarkAsPassive();
            Assert.False(_sample.IsActive());
        }
        [Fact]
        public void IsPassive_Should_Return_True()
        {
            _sample.MarkAsPassive();
            Assert.True(_sample.IsPassive());
        }
        [Fact]
        public void IsPassive_Should_Return_False()
        {
            _sample.MarkAsActive();
            Assert.False(_sample.IsPassive());
        }
        [Fact]
        public void IsDeleted_Should_Return_True()
        {
            _sample.MarkAsDeleted();
            Assert.True(_sample.IsDeleted());
        }
        [Fact]
        public void IsDeleted_Should_Return_False()
        {
            _sample.MarkAsPassive();
            Assert.False(_sample.IsDeleted());
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
        private class Sample2 : BaseDomain<string>
        {
            public Sample2(string id, string name, BaseStatus status)
            {
                Id = id;
                Name = name;
                Status = status;
            }
            public string Name { get; private set; }
        }
        private class Sample3 : BaseDomain<object>
        {
            public Sample3(object id, string name, BaseStatus status)
            {
                Id = id;
                Name = name;
                Status = status;
            }
            public string Name { get; private set; }
        }
    }
}
