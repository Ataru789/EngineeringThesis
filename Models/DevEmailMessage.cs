using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Models
{
    public class DevEmailMessage
    {
        public int Id { get; set; }

        [Required, EmailAddress, MaxLength(254)]
        public string ToEmail { get; set; } = string.Empty;

        [Required, MaxLength(254)]
        public string ToNormalizedEmail { get; set; } = string.Empty;

        [Required, MaxLength(200)]
        public string Subject { get; set; } = string.Empty;
        [Required] public string Body { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public bool IsRead { get; set; }
    }
}
