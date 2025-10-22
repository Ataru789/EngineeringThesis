using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Models
{
    [Index(nameof(NormalizedEmail), IsUnique = true)]
    [Index(nameof(NormalizedUsername), IsUnique = true)]
    public class User
    {
        public int Id { get; set; }
        [EmailAddress]
        public required string Email { get; set; }
        public required string NormalizedEmail { get; set; }

        public required string Username { get; set; }
        public required string NormalizedUsername { get; set; }

        public required byte[] PasswordHash { get; set; }
        public required byte[] PasswordSalt { get; set; }

        public string KdfAlgorithm { get; set; } = "PBKDF2";
        public string Prf { get; set; } = "HMACSHA256";
        public required int Iterations { get; set; }

        public bool IsEmailConfirmed { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public int FailedLoginCount { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }

        public ICollection<UserToken> UserTokens { get; set; } = new List<UserToken>();

        public SecurityQuestion SecurityQuestion { get; set; }
        public required byte[] SecurityAnswerHash { get; set; } 
        public required byte[] SecurityAnswerSalt { get; set; } 
        public bool TwoFactorEnabled { get; set; }
        public required byte[] TwoFactorSecret { get; set; }

    }
}
