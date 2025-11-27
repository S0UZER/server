using System.Collections.Concurrent;

namespace TodoApi.Services
{
    public class NonceStorage
    {
        private readonly ConcurrentDictionary<string, (string DeviceId, DateTime Created)> _nonces = new();
        private readonly TimeSpan _expirationTime = TimeSpan.FromMinutes(3);

        public void Add(string nonce, string deviceId)
        {
            _nonces[nonce] = (deviceId, DateTime.UtcNow);
            
            // Очистка устаревших nonce
            CleanupExpired();
        }

        public bool TryGet(string nonce, out string deviceId)
        {
            deviceId = null;
            
            if (string.IsNullOrEmpty(nonce))
                return false;

            if (_nonces.TryGetValue(nonce, out var data))
            {
                // Проверяем не истек ли nonce
                if (DateTime.UtcNow - data.Created < _expirationTime)
                {
                    deviceId = data.DeviceId;
                    return true;
                }
                
                _nonces.TryRemove(nonce, out _);
            }
            
            return false;
        }

        public void Remove(string nonce)
        {
            if (!string.IsNullOrEmpty(nonce))
            {
                _nonces.TryRemove(nonce, out _);
            }
        }

        private void CleanupExpired()
        {
            var expired = _nonces.Where(x => DateTime.UtcNow - x.Value.Created > _expirationTime)
                                .Select(x => x.Key)
                                .ToList();
            
            foreach (var nonce in expired)
            {
                _nonces.TryRemove(nonce, out _);
            }
        }
    }
}