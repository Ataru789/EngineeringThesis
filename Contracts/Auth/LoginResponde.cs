namespace EngineeringThesis.Contracts.Auth
{
    public sealed class LoginResponse
    {
        public int UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public DateTimeOffset? ExpiresAt { get; set; }
    }
}
