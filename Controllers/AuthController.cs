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

            //if (!ValidateTelegramData(req.TelegramData))
            //{
            //    _logger.LogWarning("Invalid Telegram signature for nonce: {Nonce}", req.Nonce);
            //    return Unauthorized(new { error = "Invalid Telegram signature" });
            //}

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

        [HttpPost("simple-test")]
        public IActionResult SimpleTest([FromBody] object data)
        {
            _logger.LogInformation("Simple test received: {Data}", 
                System.Text.Json.JsonSerializer.Serialize(data));
            
            return Ok(new { 
                message = "Server is working!", 
                received = data,
                timestamp = DateTime.UtcNow
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
                    new Claim("device_id", deviceId),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                },
                expires: DateTime.UtcNow.AddMinutes(
                    int.Parse(_config["Jwt:LifetimeMinutes"] ?? "60")
                ),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [HttpPost("simple-token")]
        [HttpGet("simple-token")] // Добавляем и GET для простоты тестирования
        public IActionResult SimpleToken()
        {
            try
            {
                // Генерируем тестовый токен без проверки аутентификации
                var telegramId = "123456789";
                var deviceId = "test_device_" + Guid.NewGuid().ToString("N")[..8];
                
                var jwt = GenerateJwt(telegramId, deviceId);

                _logger.LogInformation("Simple token generated for test user: {TelegramId}", telegramId);

                return Ok(new
                {
                    success = true,
                    token = jwt,
                    telegramId = telegramId,
                    deviceId = deviceId,
                    message = "Simple token for testing - NO AUTH REQUIRED",
                    generatedAt = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating simple token");
                return StatusCode(500, new { 
                    success = false,
                    error = ex.Message,
                    details = "Check server logs for more information"
                });
            }
        }

        // -------------------------
        // GET endpoint для Telegram Widget
        // -------------------------
        [HttpGet("telegram-callback")]
        public IActionResult TelegramCallback(
            [FromQuery] string id,
            [FromQuery] string first_name, 
            [FromQuery] string username,
            [FromQuery] string photo_url,
            [FromQuery] string auth_date,
            [FromQuery] string hash)
        {
            try
            {
                _logger.LogInformation("=== 🔐 TELEGRAM CALLBACK STARTED ===");
                _logger.LogInformation("📱 User Data: ID={UserId}, Name={FirstName}, Username={Username}", 
                    id, first_name, username);
                _logger.LogInformation("📅 Auth date: {AuthDate}, Hash: {Hash}", auth_date, hash);
                
                // Логируем ВСЕ query параметры
                _logger.LogInformation("🔍 All query parameters:");
                foreach (var query in Request.Query)
                {
                    _logger.LogInformation("   {Key} = {Value}", query.Key, query.Value);
                }

                // Парсим nonce из URL
                var nonce = Request.Query["nonce"].FirstOrDefault();
                _logger.LogInformation("🔑 Nonce from URL: {Nonce}", nonce ?? "NULL");
                
                string deviceId;
                if (!string.IsNullOrEmpty(nonce))
                {
                    // Если есть nonce, используем привязанный deviceId
                    if (!_nonceStorage.TryGet(nonce, out deviceId))
                    {
                        _logger.LogWarning("❌ Invalid nonce in Telegram callback: {Nonce}", nonce);
                        return BadRequest("Invalid or expired nonce");
                    }
                    _nonceStorage.Remove(nonce);
                    _logger.LogInformation("✅ Valid nonce found, DeviceId: {DeviceId}", deviceId);
                }
                else
                {
                    // Если нет nonce, генерируем временный deviceId
                    deviceId = "web_" + Guid.NewGuid().ToString("N")[..8];
                    _logger.LogWarning("⚠️ No nonce provided, generated DeviceId: {DeviceId}", deviceId);
                }

                // Генерируем JWT токен
                _logger.LogInformation("🔨 Generating JWT token...");
                var jwt = GenerateJwt(id, deviceId);
                _logger.LogInformation("✅ JWT token generated successfully");

                // Получаем URL для редиректа из конфига
                var frontendUrl = _config["Frontend:Url"] ?? "https://2ca7618e23c1aa.lhr.life";
                _logger.LogInformation("🌐 Frontend URL: {FrontendUrl}", frontendUrl);
                
                // Редирект с токеном в параметрах URL
                var redirectUrl = $"{frontendUrl}/telegram-login.html?token={jwt}&telegramId={id}&deviceId={deviceId}&success=true";
                
                _logger.LogInformation("🔄 Redirecting to: {RedirectUrl}", redirectUrl);
                _logger.LogInformation("=== ✅ TELEGRAM CALLBACK COMPLETED ===");
                
                return Redirect(redirectUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "=== ❌ TELEGRAM CALLBACK FAILED ===");
                
                var frontendUrl = _config["Frontend:Url"] ?? "https://2ca7618e23c1aa.lhr.life";
                var errorRedirectUrl = $"{frontendUrl}/telegram-login.html?error=auth_failed&message={ex.Message}";
                
                _logger.LogInformation("🔄 Redirecting to error page: {ErrorRedirectUrl}", errorRedirectUrl);
                
                return Redirect(errorRedirectUrl);
            }
        }

        [HttpGet("debug-logs")]
public IActionResult DebugLogs()
{
    try
    {
        _logger.LogInformation("=== 🧪 DEBUG LOGS ENDPOINT CALLED ===");
        _logger.LogInformation("🕒 Time: {Time}", DateTime.UtcNow);
        _logger.LogInformation("🌐 Server: {Server}", _config["Server:PublicUrl"]);
        _logger.LogInformation("📱 Frontend: {Frontend}", _config["Frontend:Url"]);
        
        // Убираем вызов GetCount или заменим на что-то другое
        _logger.LogInformation("🔑 Nonce Storage: Active (implementation details hidden)");
        
        return Ok(new { 
            message = "Debug logs written to server",
            timestamp = DateTime.UtcNow,
            server = _config["Server:PublicUrl"],
            frontend = _config["Frontend:Url"],
            status = "Server is running"
        });
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Error in debug logs endpoint");
        return StatusCode(500, new { error = ex.Message });
    }
}
        [HttpGet("debug-nonce/{nonce}")]
        public IActionResult DebugNonce(string nonce)
        {
            var exists = _nonceStorage.TryGet(nonce, out string deviceId);
            
            return Ok(new {
                nonce = nonce,
                exists = exists,
                deviceId = deviceId,
                allNonces = "Add logging to NonceStorage to see all"
            });
        }

        [HttpPost("verify-callback")]
        public IActionResult VerifyCallback([FromForm] string id, [FromForm] string first_name, 
                                        [FromForm] string username, [FromForm] string auth_date, 
                                        [FromForm] string hash, [FromQuery] string nonce)
        {
            _logger.LogInformation("Telegram callback received for user: {UserId}", id);
            
            if (!_nonceStorage.TryGet(nonce, out string deviceId))
            {
                return Unauthorized("Invalid nonce");
            }

            var telegramData = new TelegramAuthData
            {
                Id = id,
                FirstName = first_name,
                Username = username,
                AuthDate = auth_date,
                Hash = hash
            };

            // Временно пропускаем проверку подписи
            var jwt = GenerateJwt(telegramData.Id, deviceId);

            return Ok(new
            {
                success = true,
                token = jwt,
                telegramId = telegramData.Id,
                deviceId = deviceId
            });
        }

        [HttpPost("verify-test")]
        public IActionResult VerifyTest([FromBody] Newtonsoft.Json.Linq.JObject rawData)
        {
            try
            {
                _logger.LogInformation("VerifyTest received: {Data}", rawData.ToString());
                
                var nonce = rawData["nonce"]?.ToString();
                var telegramData = rawData["telegramData"] as Newtonsoft.Json.Linq.JObject;

                if (string.IsNullOrEmpty(nonce) || telegramData == null)
                {
                    return BadRequest(new { error = "Invalid request format" });
                }

                if (!_nonceStorage.TryGet(nonce, out string deviceId))
                {
                    return Unauthorized(new { error = "Invalid nonce" });
                }

                var telegramId = telegramData["Id"]?.ToString();
                
                if (string.IsNullOrEmpty(telegramId))
                {
                    return BadRequest(new { error = "Telegram ID is required" });
                }

                _logger.LogInformation("Manual verification for user: {UserId}", telegramId);

                var jwt = GenerateJwt(telegramId, deviceId);

                return Ok(new
                {
                    success = true,
                    token = jwt,
                    telegramId = telegramId,
                    deviceId = deviceId,
                    debug = "manual_verification"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in VerifyTest");
                return StatusCode(500, new { error = ex.Message, details = ex.StackTrace });
            }
        }
    }
}