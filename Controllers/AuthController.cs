using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using TodoApi.Models;
using TodoApi.Services;

namespace TodoApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly NonceStorage _nonceStorage;

        public AuthController(IConfiguration config, NonceStorage ns)
        {
            _config = config;
            _nonceStorage = ns;
        }

        // -------------------------
        // 1) /auth/start
        // -------------------------
        [HttpPost("start")]
        public IActionResult StartAuth()
        {
            var nonce = Guid.NewGuid().ToString("N");

            _nonceStorage.Add(nonce);

            var redirectUrl = $"{_config["Server:PublicUrl"]}/telegram-login.html?nonce={nonce}";

            return Ok(new StartAuthResponse
            {
                Nonce = nonce,
                LoginUrl = redirectUrl
            });
        }


        // -------------------------
        // 2) /auth/verify
        // -------------------------
        [HttpPost("verify")]
        public IActionResult Verify([FromBody] AuthVerifyRequest req)
        {
            if (!_nonceStorage.Exists(req.Nonce))
                return Unauthorized("Nonce not found or expired");

            if (!ValidateTelegramData(req.TelegramData))
                return Unauthorized("Invalid Telegram signature");

            _nonceStorage.Remove(req.Nonce);

            var jwt = GenerateJwt(req.TelegramData.Id);

            return Ok(new
            {
                success = true,
                token = jwt
            });
        }


        private bool ValidateTelegramData(TelegramAuthData data)
        {
            var botToken = _config["TelegramBot:Token"];

            var authDict = new Dictionary<string, string>
            {
                { "id", data.Id },
                { "first_name", data.FirstName },
                { "username", data.Username },
                { "auth_date", data.AuthDate }
            };

            var dataCheckString = string.Join("\n",
                authDict.OrderBy(k => k.Key).Select(k => $"{k.Key}={k.Value}"));

            var key = SHA256.HashData(Encoding.UTF8.GetBytes(botToken));
            using var hmac = new HMACSHA256(key);

            var hash = BitConverter.ToString(
                hmac.ComputeHash(Encoding.UTF8.GetBytes(dataCheckString)))
                .Replace("-", "")
                .ToLower();

            return hash == data.Hash;
        }


        private string GenerateJwt(string telegramId)
        {
            // простой JWT без ролей, чтобы работало
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"fake-jwt-for-{telegramId}-{Guid.NewGuid()}"
            ));
        }
    }
}
