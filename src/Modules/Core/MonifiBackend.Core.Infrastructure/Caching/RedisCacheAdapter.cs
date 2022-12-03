using MonifiBackend.Core.Domain.Caching;
using System.Text.Json;

namespace MonifiBackend.Core.Infrastructure.Caching
{
    public class RedisCacheAdapter : ICachePort
    {
        private RedisServer _redisServer;

        public RedisCacheAdapter(RedisServer redisServer)
        {
            _redisServer = redisServer;
        }

        public void Add(string key, object data)
        {
            string jsonData = JsonSerializer.Serialize(data);
            _redisServer.Database.StringSet(key, jsonData);
        }

        public bool Any(string key)
        {
            return _redisServer.Database.KeyExists(key);
        }

        public T Get<T>(string key)
        {
            if (Any(key))
            {
                string jsonData = _redisServer.Database.StringGet(key);
                return JsonSerializer.Deserialize<T>(jsonData);
            }

            return default;
        }

        public void Remove(string key)
        {
            _redisServer.Database.KeyDelete(key);
        }

        public void Clear()
        {
            _redisServer.FlushDatabase();
        }
    }
}
