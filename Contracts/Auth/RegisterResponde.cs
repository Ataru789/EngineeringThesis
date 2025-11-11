namespace EngineeringThesis.Contracts.Auth
{
    public sealed class RegisterResponse
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public int SecurityQuestion { get; set; }

    }
}