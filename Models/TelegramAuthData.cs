using Newtonsoft.Json;

namespace TodoApi.Models
{
    public class TelegramAuthData
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("first_name")]
        public string FirstName { get; set; }

        [JsonProperty("username")]
        public string Username { get; set; }

        [JsonProperty("auth_date")]
        public string AuthDate { get; set; }

        [JsonProperty("hash")]
        public string Hash { get; set; }
    }
}
