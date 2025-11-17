using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using TodoApi.Models;

namespace TodoApi.Services
{
    public class TelegramService : ITelegramService
    {
        private readonly ITelegramBotClient _botClient;
        private readonly ILogger<TelegramService> _logger;
        private readonly IConfiguration _configuration;

        public TelegramService(IConfiguration configuration, ILogger<TelegramService> logger)
        {
            _configuration = configuration;
            _logger = logger;
            
            var botToken = _configuration["TelegramBot:Token"];
            if (string.IsNullOrEmpty(botToken))
            {
                throw new ArgumentException("Telegram bot token is not configured");
            }
            
            _botClient = new TelegramBotClient(botToken);
        }

        public async Task<SendMessageResult> SendMessageAsync(long chatId, string message)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(message))
                {
                    return new SendMessageResult 
                    { 
                        Success = false, 
                        Error = "Message cannot be empty" 
                    };
                }

                var sentMessage = await _botClient.SendTextMessageAsync(
                    chatId: chatId,
                    text: message,
                    parseMode: ParseMode.Html
                );

                _logger.LogInformation("Message sent to chat {ChatId}, message ID: {MessageId}", 
                    chatId, sentMessage.MessageId);

                return new SendMessageResult 
                { 
                    Success = true, 
                    MessageId = sentMessage.MessageId.ToString() 
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending message to chat {ChatId}", chatId);
                return new SendMessageResult 
                { 
                    Success = false, 
                    Error = ex.Message 
                };
            }
        }

        public async Task<bool> TestConnectionAsync()
        {
            try
            {
                var me = await _botClient.GetMeAsync();
                _logger.LogInformation("Bot connection test successful. Bot: @{BotUsername}", me.Username);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Bot connection test failed");
                return false;
            }
        }
    }
}