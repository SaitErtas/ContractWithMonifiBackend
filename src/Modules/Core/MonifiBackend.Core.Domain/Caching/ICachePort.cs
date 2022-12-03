namespace MonifiBackend.Core.Domain.Caching
{
    public interface ICachePort
    {
        T Get<T>(string key);
        void Add(string key, object data);
        void Remove(string key);
        void Clear();
        bool Any(string key);
    }
}
