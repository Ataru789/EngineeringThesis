using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Contracts.Auth
{
    public sealed class PasswordlessLoginStartRequest
    {
        [Required, MaxLength(254)]
        public string Identifier { get; set; } = string.Empty; 
    }

    public sealed class PasswordlessLoginStartResponse
    {
        public int? SecurityQuestion { get; set; } 
        public int ExpiresInSeconds { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public sealed class PasswordlessLoginConfirmRequest
    {
        [Required, MaxLength(254)]
        public string Identifier { get; set; } = string.Empty; 

        [Required, MinLength(6), MaxLength(64)]
        public string Code { get; set; } = string.Empty; 

        [Required, MinLength(2), MaxLength(200)]
        public string SecurityAnswer { get; set; } = string.Empty;

       
        [MinLength(6), MaxLength(6)]
        public string? TwoFactorCode { get; set; }
    }
}
