namespace MonifiBackend.Core.Domain.Resources
{
    public class QueryObject
    {
        public QueryObject(string sortBy, bool ısSortAscending, int page, byte pageSize)
        {
            SortBy = sortBy;
            IsSortAscending = ısSortAscending;
            Page = page;
            PageSize = pageSize;
        }

        public string SortBy { get; set; }
        public bool IsSortAscending { get; set; }
        public int Page { get; set; }
        public byte PageSize { get; set; }
    }
}
