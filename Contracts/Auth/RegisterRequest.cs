using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Contracts.Auth
{
    public class RegisterRequest
    {
        [Required(ErrorMessage = "Adres email jest wymagany")]
        [EmailAddress(ErrorMessage ="Niepoprawny adres email")]
        [MaxLength(254, ErrorMessage = "Maksymalna długość to 254")]
        public string Email { get; set; } = string.Empty;
        [Required(ErrorMessage = "Nazwa użytkownika jest wymagana")]
        [MinLength(3, ErrorMessage = "Minamalna długość to 3")]
        [MaxLength(20, ErrorMessage = "Maksymalna długoś to 20")]
        public string Username { get; set; } = string.Empty;
        [Required(ErrorMessage = "Hasło jest wymagane")]
        [MinLength(8, ErrorMessage = "Minimalna długość to 8")]
        [MaxLength(100, ErrorMessage = "Maksymalna długość to 100")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", ErrorMessage = "Hasło musi zawierać co najmniej jedną wielką literę, jedną małą literę, jedną cyfrę oraz jeden znak specjalny oraz conajmniej 8 znaków")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;
        [Required(ErrorMessage = "Potwierdzenie hasła jest wymagane")]
        [Compare("Password", ErrorMessage = "Hasła muszą być identyczne")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        [Range(0, 10)]
        public int SecurityQuestion { get; set; }

        [Required]
        [MinLength(2), MaxLength(200)]
        public string SecurityAnswer { get; set; } = string.Empty;
    }
}
