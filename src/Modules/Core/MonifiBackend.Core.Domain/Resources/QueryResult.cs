namespace MonifiBackend.Core.Domain.Resources
{
    public class QueryResult<TEntity>
    {
        public QueryResult(int totalItems, List<TEntity> ıtems)
        {
            TotalItems = totalItems;
            Items = ıtems;
        }

        public int TotalItems { get; set; }
        public List<TEntity> Items { get; set; }
    }
}
