using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using TodoApi.Models;
using TodoApi.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace TodoApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly NonceStorage _nonceStorage;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IConfiguration config, NonceStorage ns, ILogger<AuthController> logger)
        {
            _config = config;
            _nonceStorage = ns;
            _logger = logger;
        }

        // -------------------------
        // 1) /auth/start - теперь принимает DeviceId
        // -------------------------
        [HttpPost("start")]
        public IActionResult StartAuth([FromBody] StartAuthRequest request)
        {
            if (string.IsNullOrEmpty(request?.DeviceId))
            {
                return BadRequest(new { error = "DeviceId is required" });
            }

            var nonce = Guid.NewGuid().ToString("N");
            
            // Сохраняем nonce с привязкой к DeviceId
            _nonceStorage.Add(nonce, request.DeviceId);

            var publicUrl = _config["Server:PublicUrl"] ?? "https://localhost:5052";
            var redirectUrl = $"{publicUrl}/telegram-login.html?nonce={nonce}";

            _logger.LogInformation("Auth started for device: {DeviceId}, nonce: {Nonce}", 
                request.DeviceId, nonce);

            return Ok(new StartAuthResponse
            {
                Nonce = nonce,
                LoginUrl = redirectUrl
            });
        }

        // -------------------------
        // 2) /auth/verify - теперь включает DeviceId в JWT
        // -------------------------
        [HttpPost("verify")]
        public IActionResult Verify([FromBody] AuthVerifyRequest req)
        {
            if (req == null)
            {
                return BadRequest(new { error = "Request body is required" });
            }

            if (!_nonceStorage.TryGet(req.Nonce, out string deviceId))
            {
                _logger.LogWarning("Invalid or expired nonce: {Nonce}", req.Nonce);
                return Unauthorized(new { error = "Nonce not found or expired" });
            }

            if (!ValidateTelegramData(req.TelegramData))
            {
                _logger.LogWarning("Invalid Telegram signature for nonce: {Nonce}", req.Nonce);
                return Unauthorized(new { error = "Invalid Telegram signature" });
            }

            _logger.LogInformation("Telegram auth successful for user: {UserId}, device: {DeviceId}", 
                req.TelegramData.Id, deviceId);

            _nonceStorage.Remove(req.Nonce);

            // Генерируем JWT с включением DeviceId
            var jwt = GenerateJwt(req.TelegramData.Id, deviceId);

            return Ok(new
            {
                success = true,
                token = jwt,
                telegramId = req.TelegramData.Id,
                deviceId = deviceId
            });
        }

        private bool ValidateTelegramData(TelegramAuthData data)
        {
            if (data == null)
                return false;

            var botToken = _config["TelegramBot:Token"];
            if (string.IsNullOrEmpty(botToken))
                return false;

            var authDict = new Dictionary<string, string>
            {
                { "id", data.Id ?? "" },
                { "first_name", data.FirstName ?? "" },
                { "username", data.Username ?? "" },
                { "auth_date", data.AuthDate ?? "" }
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

        private string GenerateJwt(string telegramId, string deviceId)
        {
            var jwtKey = _config["Jwt:Key"];
            if (string.IsNullOrEmpty(jwtKey))
            {
                throw new ArgumentException("JWT Key is not configured");
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: new[]
                {
                    new Claim("telegram_id", telegramId),
                    new Claim("device_id", deviceId ?? ""),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                },
                expires: DateTime.UtcNow.AddMinutes(
                    int.Parse(_config["Jwt:LifetimeMinutes"] ?? "60")
                ),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}