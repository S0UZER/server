using System.Collections.Concurrent;

namespace TodoApi.Services
{
    public class NonceStorage
    {
        private readonly ConcurrentDictionary<string, DateTime> _nonces = new();

        public void Add(string nonce)
        {
            _nonces[nonce] = DateTime.UtcNow;
        }

        public bool Exists(string nonce)
        {
            return _nonces.ContainsKey(nonce);
        }

        public void Remove(string nonce)
        {
            _nonces.TryRemove(nonce, out _);
        }
    }
}
