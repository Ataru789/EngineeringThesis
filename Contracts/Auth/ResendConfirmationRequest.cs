using System.ComponentModel.DataAnnotations;

namespace EngineeringThesis.Contracts.Auth
{
    public sealed class ResendConfirmationRequest
    {
        [Required, EmailAddress, MaxLength(254)]
        public string Email { get; set; } = string.Empty;
    }
}
