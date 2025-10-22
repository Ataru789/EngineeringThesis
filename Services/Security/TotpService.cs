using System.Security.Cryptography;

namespace EngineeringThesis.Services.Security
{
    public sealed class TotpService : ITotpService
    {
        private const int StepSeconds = 60;
        private const int Digits = 6;
        public string GenerateCode(byte[] secret, DateTimeOffset? now = null)
        {
            now ??= DateTimeOffset.UtcNow;
            var counter = (long)Math.Floor(now.Value.ToUnixTimeSeconds() / (double)StepSeconds);
            return GenerateAt(secret, counter);
        }
        public bool VerifyCode(byte[] secret, string code, DateTimeOffset? now = null, int allowedDriftSteps = 1)
        {
            if (string.IsNullOrWhiteSpace(code) || code.Length != Digits) return false;
            now ??= DateTimeOffset.UtcNow;
            var current = (long)Math.Floor(now.Value.ToUnixTimeSeconds() / (double)StepSeconds);
            for (long c = current - allowedDriftSteps; c <= current + allowedDriftSteps; c++)
            {
                if (GenerateAt(secret, c) == code) return true;
            }
            return false;
        }
        public int SecondsUntilNextStep(DateTimeOffset? now = null)
        {
            now ??= DateTimeOffset.UtcNow;
            var s = (int)(now.Value.ToUnixTimeSeconds() % StepSeconds);
            return StepSeconds - s;
        }
        private static string GenerateAt(byte[] secret, long counter)
        {
            var counterBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(counter));
            using var hmac = new HMACSHA1(secret);
            var hash = hmac.ComputeHash(counterBytes);
            int offset = hash[^1] & 0x0F;
            int binary = ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);
            int otp = binary % (int)Math.Pow(10, Digits);
            return otp.ToString(new string('0', Digits));
        }
    }
}