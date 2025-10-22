using System.Security.Cryptography;

namespace EngineeringThesis.Services.Security
{
    public interface IPasswordHasher
    {
        PasswordHashResult ComputeHash(string plainPassword);
        bool Verify(string plainPassword, byte[] salt, string prf, int iterations, string alg, byte[] expectedHash);
        bool NeedsRehash(string prf, int iterations);
    }

    public sealed class PasswordHashResult
    {
        public byte[] Hash { get; init; } = Array.Empty<byte>();   
        public byte[] Salt { get; init; } = Array.Empty<byte>();   
        public string KdfAlgorithm { get; init; } = "PBKDF2";
        public string Prf { get; init; } = "HMACSHA256";
        public int Iterations { get; init; }
    }
    public sealed class Pbkdf2PasswordHasher : IPasswordHasher
    {
        private const int SaltLength = 16;             
        private const int HashLength = 32;             
        private const string Algorithm = "PBKDF2";    
        private const string PrfName = "HMACSHA256";  

        private const int DefaultIterations = 200_000;

        public PasswordHashResult ComputeHash(string plainPassword)
        {
            if (plainPassword is null) throw new ArgumentNullException(nameof(plainPassword));

            var salt = RandomNumberGenerator.GetBytes(SaltLength);

            var hash = DerivePbkdf2Sha256(plainPassword, salt, DefaultIterations, HashLength);

            return new PasswordHashResult
            {
                Hash = hash,
                Salt = salt,
                KdfAlgorithm = Algorithm,
                Prf = PrfName,
                Iterations = DefaultIterations
            };
        }

        public bool Verify(string plainPassword, byte[] salt, string prf, int iterations, string alg, byte[] expectedHash)
        {
            if (plainPassword is null) return false;
            if (salt is null || expectedHash is null) return false;
            if (!string.Equals(alg, Algorithm, StringComparison.Ordinal)) return false;
            if (!string.Equals(prf, PrfName, StringComparison.Ordinal)) return false;
            if (iterations <= 0) return false;
            if (expectedHash.Length != HashLength) return false;
            if (salt.Length != SaltLength) return false;

            var actual = DerivePbkdf2Sha256(plainPassword, salt, iterations, HashLength);

            return CryptographicOperations.FixedTimeEquals(actual, expectedHash);
        }

        public bool NeedsRehash(string prf, int iterations)
        {
            if (!string.Equals(prf, PrfName, StringComparison.Ordinal)) return true;
            return iterations < DefaultIterations;
        }

        private static byte[] DerivePbkdf2Sha256(string password, byte[] salt, int iterations, int length)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(length);
        }
    }
}
