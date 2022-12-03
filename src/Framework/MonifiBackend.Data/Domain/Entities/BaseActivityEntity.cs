namespace MonifiBackend.Data.Domain.Entities
{
    public class BaseActivityEntity : BaseEntity
    {
        public DateTime CreatedAt { get; set; }
        public DateTime ModifiedAt { get; set; }
    }
}
