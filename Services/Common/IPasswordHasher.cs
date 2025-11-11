using EngineeringThesis.Services.Security;

namespace EngineeringThesis.Services.Security
{
    public interface IPasswordHasher
    {
        PasswordHashResult ComputeHash(string plainPassword);
        bool Verify(string plainPassword, byte[] salt, string prf, int iterations, string alg, byte[] expectedHash);
        bool NeedsRehash(string prf, int iterations);
    }
}
