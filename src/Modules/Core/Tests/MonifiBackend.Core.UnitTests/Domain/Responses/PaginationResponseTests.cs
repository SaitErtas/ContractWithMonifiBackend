using MonifiBackend.Core.Domain.Responses;
using Xunit;

namespace MonifiBackend.Core.UnitTests.Domain.Responses
{
    public class PaginationResponseTests
    {
        [Fact]
        public void PaginationResponse_Should_Be_Successful_Empty()
        {
            var page = 0;
            var pageSize = 0;
            var totalPage = 0;
            var totalRecords = 0;

            var sample = new PaginationResponse();

            Assert.Equal(sample.Page, page);
            Assert.Equal(sample.PageSize, pageSize);
            Assert.Equal(sample.TotalPage, totalPage);
            Assert.Equal(sample.TotalRecords, totalRecords);
        }
        [Fact]
        public void PaginationResponse_Should_Be_Successful()
        {
            var page = 200;
            var pageSize = 1;
            var totalPage = 1;
            var totalRecords = 0;

            var sample = new PaginationResponse(page, pageSize);

            Assert.Equal(sample.Page, page);
            Assert.Equal(sample.PageSize, pageSize);
            Assert.Equal(sample.TotalPage, totalPage);
            Assert.Equal(sample.TotalRecords, totalRecords);
        }
        [Fact]
        public void PaginationResponse_Should_Be_Successful_Total()
        {
            var page = 200;
            var pageSize = 1;
            var totalPage = 2;
            var totalRecords = 3;

            var sample = new PaginationResponse(page, pageSize, totalPage, totalRecords);

            Assert.Equal(sample.Page, page);
            Assert.Equal(sample.PageSize, pageSize);
            Assert.Equal(sample.TotalPage, totalPage);
            Assert.Equal(sample.TotalRecords, totalRecords);
        }
    }
}
