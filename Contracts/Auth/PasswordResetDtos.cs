using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Contracts.Auth
{
    public sealed class PasswordResetRequest
    {
        [Required, EmailAddress, MaxLength(254)]
        public string Email { get; set; } = string.Empty;
    }
    public sealed class PasswordResetRequestResponse
    {
        public int? SecurityQuestion { get; set; } 
        public int ExpiresInSeconds { get; set; }
        public string Message { get; set; } = string.Empty;
    }
    public sealed class PasswordResetConfirmRequest
    {
        [Required, EmailAddress, MaxLength(254)]
        public string Email { get; set; } = string.Empty;


        [Required, MinLength(6), MaxLength(64)]
        public string Code { get; set; } = string.Empty; 

        [Required]
        [MinLength(2), MaxLength(200)]
        public string SecurityAnswer { get; set; } = string.Empty;

        [Required(ErrorMessage = "Hasło jest wymagane")]
        [MinLength(8, ErrorMessage = "Minimalna długość to 8")]
        [MaxLength(100, ErrorMessage = "Maksymalna długość to 100")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", ErrorMessage = "Hasło musi zawierać co najmniej jedną wielką literę, jedną małą literę, jedną cyfrę oraz jeden znak specjalny.")]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; } = string.Empty;
    }
}