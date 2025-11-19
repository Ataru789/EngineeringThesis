using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Models
{
    public class DevEmailMessage
    {
        public int Id { get; set; }
        public string ToEmail { get; set; } = string.Empty;
        public string ToNormalizedEmail { get; set; } = string.Empty;
        public string Subject { get; set; } = string.Empty;
        [Required] public string Body { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
    }
}
