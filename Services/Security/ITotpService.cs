namespace EngineeringThesis.Services.Security
{
    public interface ITotpService
    {
        string GenerateCode(byte[] secret, DateTimeOffset? now = null);
        bool VerifyCode(byte[] secret, string code, DateTimeOffset? now = null, int allowedDriftSteps = 1);
        int SecondsUntilNextStep(DateTimeOffset? now = null);
    }
}