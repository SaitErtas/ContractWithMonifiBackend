using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace MonifiBackend.Data.Domain.Entities.Configurations
{
    public static class BaseActivityConfiguration
    {
        public static void Configure<T>(EntityTypeBuilder<T> builder) where T : BaseActivityEntity
        {
            BaseConfiguration.Configure<T>(builder);

            builder.Property(x => x.CreatedAt).IsRequired();
            builder.Property(x => x.ModifiedAt).IsRequired();
        }
    }
}
