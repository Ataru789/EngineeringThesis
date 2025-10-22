using System.Security.Cryptography;
using System.Text;

namespace EngineeringThesis.Services.Security
{
    public static class EmailVerification
    {
        public static (string code, byte[] hash) NewCode()
        {
            int value = RandomNumberGenerator.GetInt32(10_000_000, 100_000_000);
            string code = value.ToString(); 
            return (code, Sha256(code));
        }
        public static byte[] Sha256(string input)
        {
            var bytes = Encoding.UTF8.GetBytes(input);
            return SHA256.HashData(bytes);
        }
    }
}
