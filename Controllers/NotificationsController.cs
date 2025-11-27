using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TodoApi.Models;
using TodoApi.Services;
using System.Reflection;
using Microsoft.Extensions.Logging;

namespace TodoApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // ← Атрибут аутентификации
    public class NotificationsController : ControllerBase
    {
        private readonly ITelegramService _telegramService;
        private readonly ILogger<NotificationsController> _logger;

        public NotificationsController(ITelegramService telegramService, ILogger<NotificationsController> logger)
        {
            _telegramService = telegramService;
            _logger = logger;
        }

        // POST: api/notifications - теперь требует аутентификации
        [HttpPost]
        public async Task<ActionResult<SendMessageResult>> SendNotification(TelegramMessage message)
        {
            try
            {
                if (message == null)
                {
                    return BadRequest(new { error = "Message is required" });
                }

                // Получаем telegram_id из JWT токена
                var telegramId = User.FindFirst("telegram_id")?.Value;
                var deviceId = User.FindFirst("device_id")?.Value;

                if (string.IsNullOrEmpty(telegramId))
                {
                    return Unauthorized(new { error = "No telegram_id in token" });
                }

                _logger.LogInformation(
                    "Sending notification for user {TelegramId} from device {DeviceId}", 
                    telegramId, deviceId);

                // Преобразуем telegramId в long (chatId)
                if (!long.TryParse(telegramId, out long userChatId))
                {
                    return BadRequest(new { error = "Invalid telegram_id format" });
                }

                // ВАЖНО: Отправляем сообщение ТОЛЬКО в чат авторизованного пользователя
                // Игнорируем message.ChatId из запроса для безопасности
                var result = await _telegramService.SendMessageAsync(userChatId, message.Message);

                return result.Success ? Ok(result) : BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending notification");
                return StatusCode(500, new SendMessageResult
                {
                    Success = false,
                    Error = "Internal server error"
                });
            }
        }

        // GET: api/notifications/test
        [HttpGet("test")]
        [AllowAnonymous] // Публичный endpoint
        public async Task<ActionResult> TestConnection()
        {
            var isConnected = await _telegramService.TestConnectionAsync();
            
            if (isConnected)
            {
                return Ok(new { message = "Bot connection successful" });
            }
            else
            {
                return BadRequest(new { message = "Bot connection failed" });
            }
        }

        // POST: api/notifications/test-message
        [HttpPost("test-message")]
        [AllowAnonymous] // Публичный endpoint
        public async Task<ActionResult<SendMessageResult>> SendTestMessage([FromQuery] long chatId)
        {
            var testMessage = $"✅ Test notification from TodoAPI!\n" +
                            $"🕒 Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC\n" +
                            $"🔧 API: TodoApi";

            var result = await _telegramService.SendMessageAsync(chatId, testMessage);
            
            if (result.Success)
            {
                return Ok(result);
            }
            else
            {
                return BadRequest(result);
            }
        }
    }
}