using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Models
{
    public enum UserTokenType
    {
        EmailConfirmation = 0,
        PasswordReset = 1,
        TwoFactorAuthentication = 2,
        RememberMe = 3
    }
    [Index(nameof(UserId), nameof(UserTokenType), nameof(ExpiresAt))]
    [Index(nameof(ValueHash), IsUnique = true)]
    public class UserToken
    {
        public int Id { get; set; }

        public int UserId { get; set; }
        public UserTokenType UserTokenType { get; set; }

        public required byte[] ValueHash { get; set; }

        public DateTimeOffset CreatedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }
        public DateTimeOffset? ConsumedAt { get; set; }

        public User? User { get; set; }
        [MaxLength(45)] public string? RequestIp { get; set; }
    }
}
