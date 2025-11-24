namespace TodoApi.Models
{
    public class AuthVerifyRequest
    {
        public string Nonce { get; set; }
        public TelegramAuthData TelegramData { get; set; }
    }
}
