using System.Diagnostics;

namespace TodoApi.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var stopwatch = Stopwatch.StartNew();
            
            // Логируем входящий запрос
            _logger.LogInformation("Incoming request: {Method} {Path}", 
                context.Request.Method, context.Request.Path);

            await _next(context);
            
            stopwatch.Stop();
            
            _logger.LogInformation("Request completed: {Method} {Path} - {StatusCode} in {ElapsedMs}ms",
                context.Request.Method, context.Request.Path, 
                context.Response.StatusCode, stopwatch.ElapsedMilliseconds);
        }
    }
}