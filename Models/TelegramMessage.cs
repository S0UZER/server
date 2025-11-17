namespace TodoApi.Models
{
    public class TelegramMessage
    {
        public long ChatId { get; set; }
        public string Message { get; set; }
        public string? PhotoUrl { get; set; }
    }

    public class SendMessageResult
    {
        public bool Success { get; set; }
        public string? MessageId { get; set; }
        public string? Error { get; set; }
    }
}