using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Contracts.Auth
{
    public sealed class ConfirmEmailRequest
    {
        [Required, EmailAddress, MaxLength(254)]
        public string Email { get; set; } = string.Empty;

        [Required, MinLength(6), MaxLength(64)]
        public string Code { get; set; } = string.Empty;
    }
}
