using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text;
using TodoApi.Models;

namespace TodoApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly string botToken;

        public AuthController(IConfiguration config)
        {
            botToken = config["TelegramBot:Token"];
        }

        [HttpPost("telegram")]
        public IActionResult TelegramLogin([FromBody] TelegramAuthData payload)
        {
            if (payload == null)
                return BadRequest("Invalid JSON");

            var dataDict = new Dictionary<string, string>
            {
                { "id", payload.Id },
                { "first_name", payload.FirstName },
                { "username", payload.Username },
                { "auth_date", payload.AuthDate },
                { "hash", payload.Hash }
            };

            if (!ValidateTelegramData(dataDict))
                return Unauthorized("Invalid Telegram signature");

            return Ok(new
            {
                success = true,
                telegramId = payload.Id
            });
        }

        private bool ValidateTelegramData(Dictionary<string, string> authData)
        {
            var checkHash = authData["hash"];
            authData.Remove("hash");

            var dataCheckString = string.Join("\n",
                authData.OrderBy(k => k.Key)
                        .Select(k => $"{k.Key}={k.Value}"));

            var key = SHA256.HashData(Encoding.UTF8.GetBytes(botToken));
            var hmac = new HMACSHA256(key);

            var hash = BitConverter
                .ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(dataCheckString)))
                .Replace("-", "")
                .ToLower();

            return hash == checkHash;
        }
    }
}
