using TodoApi.Models;

namespace TodoApi.Services
{
    public interface ITelegramService
    {
        Task<SendMessageResult> SendMessageAsync(long chatId, string message);
        Task<bool> TestConnectionAsync();
    }
}