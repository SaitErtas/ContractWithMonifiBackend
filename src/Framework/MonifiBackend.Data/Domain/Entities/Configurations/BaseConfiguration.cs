using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MonifiBackend.Data.Domain.Entities.Configurations
{
    internal static class BaseConfiguration
    {
        public static void Configure<T>(EntityTypeBuilder<T> builder) where T : BaseEntity
        {
            builder.HasKey(q => q.Id);
            builder.Property(q => q.Id).ValueGeneratedOnAdd();
            builder.Property(x => x.Status).IsRequired();
        }
    }
}
