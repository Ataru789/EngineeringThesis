
using System.Text;
using System.Text.RegularExpressions;

namespace EngineeringThesis.Services.Common
{
    public static class Normalization
    {
        private static readonly Regex UsernameAllowedRegex = new(@"^[A-Za-z0-9._-]+$", RegexOptions.Compiled);
        public static string NormalizeEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email)) return string.Empty;
            var trimmed = email.Trim();

            var normalized = trimmed.Normalize(NormalizationForm.FormC).ToUpperInvariant();
            return normalized;
        }

        public static string NormalizeUsername(string? username)
        {
            if (string.IsNullOrWhiteSpace(username)) return string.Empty;
            var trimmed = username.Trim();
            var normalized = trimmed.Normalize(NormalizationForm.FormC).ToUpperInvariant();
            return normalized;
        }
        public static bool IsValidUsername(string? username)
        {
            if (string.IsNullOrEmpty(username)) return false;
            if (username.Length < 3 || username.Length > 20) return false;
            return UsernameAllowedRegex.IsMatch(username);
        }
    }
}
