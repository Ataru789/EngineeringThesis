using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Contracts.Auth
{
    public sealed class LoginRequest
    {
        [Required(ErrorMessage = "Podaj email lub nazwę użytkownika.")]
        [MaxLength(254)]
        public string Identifier { get; set; } = string.Empty;

        [Required(ErrorMessage = "Hasło jest wymagane.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [MinLength(6), MaxLength(6)]
        public string? TwoFactorCode { get; set; }
    }
}
