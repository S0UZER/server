using Microsoft.EntityFrameworkCore;
using TodoApi.Models;
using TodoApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using TodoApi.Middleware; // Добавьте эту using директиву

var builder = WebApplication.CreateBuilder(args);

// Конфигурация JWT - ДОБАВЛЕНА ПРОВЕРКА НА NULL
var jwtSettings = builder.Configuration.GetSection("Jwt");
var jwtKey = jwtSettings["Key"];
if (string.IsNullOrEmpty(jwtKey))
{
    throw new ArgumentException("JWT Key is not configured in appsettings.json");
}
var key = Encoding.UTF8.GetBytes(jwtKey);

// Аутентификация JWT
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

// Настройка хоста
builder.WebHost.UseUrls("http://localhost:5052");

// Сервисы
builder.Services
    .AddControllers()
    .AddNewtonsoftJson();

// Регистрация сервисов
builder.Services.AddSingleton<NonceStorage>();
builder.Services.AddScoped<ITelegramService, TelegramService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<TodoContext>(opt =>
    opt.UseInMemoryDatabase("TodoList"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "TodoAPI V1");
        c.RoutePrefix = "swagger"; // Явно указываем путь
    });
}

app.UseHttpsRedirection();

app.UseMiddleware<RequestLoggingMiddleware>();

app.UseAuthentication();
app.UseAuthorization();
app.UseStaticFiles();
app.MapControllers();

app.MapGet("/", () => "TodoAPI is running! Go to /swagger");

app.Run();