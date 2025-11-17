using Microsoft.AspNetCore.Mvc;
using TodoApi.Models;
using TodoApi.Services;

namespace TodoApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class NotificationsController : ControllerBase
    {
        private readonly ITelegramService _telegramService;
        private readonly ILogger<NotificationsController> _logger;

        public NotificationsController(ITelegramService telegramService, ILogger<NotificationsController> logger)
        {
            _telegramService = telegramService;
            _logger = logger;
        }

        // POST: api/notifications
        [HttpPost]
        public async Task<ActionResult<SendMessageResult>> SendNotification(TelegramMessage message)
        {
            try
            {
                _logger.LogInformation("Sending notification to chat {ChatId}", message.ChatId);
                
                var result = await _telegramService.SendMessageAsync(message.ChatId, message.Message);
                
                if (result.Success)
                {
                    return Ok(result);
                }
                else
                {
                    return BadRequest(result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending notification to chat {ChatId}", message.ChatId);
                return StatusCode(500, new SendMessageResult 
                { 
                    Success = false, 
                    Error = "Internal server error" 
                });
            }
        }

        // GET: api/notifications/test
        [HttpGet("test")]
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