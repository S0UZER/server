using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using TodoApi.Models;
using TodoApi.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;


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
            Console.WriteLine("RECEIVED:");
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(req));


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
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_config["Jwt:Key"])
            );

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: new[]
                {
                    new Claim("telegram_id", telegramId)
                },
                expires: DateTime.UtcNow.AddMinutes(
                    int.Parse(_config["Jwt:LifetimeMinutes"])
                ),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
