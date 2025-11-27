namespace TodoApi.Models
{
    public class StartAuthRequest
    {
        public string DeviceId { get; set; } = "default_device";
        public string AppVersion { get; set; } = "1.0.0";
        public string AppName { get; set; } = "TodoMobileApp";
    }
}