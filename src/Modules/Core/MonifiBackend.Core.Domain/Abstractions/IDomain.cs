using MonifiBackend.Core.Domain.Base;

namespace MonifiBackend.Core.Domain.Abstractions
{
    public interface IDomain : IReadOnlyDomain
    {
        void MarkAsActive();
        void MarkAsPassive();
        void MarkAsDeleted();

        void SetStatus(BaseStatus status);
    }
}
