using EngineeringThesis.Contracts.Auth;
using EngineeringThesis.Data;
using EngineeringThesis.Models;
using EngineeringThesis.Services.Common;
using EngineeringThesis.Services.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;

namespace EngineeringThesis.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public sealed class AuthController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ITotpService _totp;

        private const int MaxFailedLogin = 3;
        private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

        public AuthController(AppDbContext db, IPasswordHasher passwordHasher, ITotpService totp)
        {
            _db = db;
            _passwordHasher = passwordHasher;
            _totp = totp;
        }

        [HttpPost("register")]
        [ProducesResponseType(typeof(RegisterResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status409Conflict)]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken ct)
        {
            if (!ModelState.IsValid)
                return ValidationProblem(ModelState);

            var normalizedEmail = Normalization.NormalizeEmail(request.Email);
            var normalizedUsername = Normalization.NormalizeUsername(request.Username);

            if (!Normalization.IsValidUsername(request.Username))
                return BadRequest(new { message = "Niedozwolone znaki w nazwie użytkownika lub zła długość (3–20)." });

            var exists = await _db.Users
                .AsNoTracking()
                .AnyAsync(u =>
                    u.NormalizedEmail == normalizedEmail ||
                    u.NormalizedUsername == normalizedUsername, ct);

            if (exists)
                return Conflict(new { message = "Email lub nazwa użytkownika jest już zajęta." });

            var hashRes = _passwordHasher.ComputeHash(request.Password);

            var secAns = _passwordHasher.ComputeHash(request.SecurityAnswer);
            var totpSecret = RandomNumberGenerator.GetBytes(20);

            var user = new User
            {
                Email = request.Email,
                Username = request.Username,
                NormalizedEmail = normalizedEmail,
                NormalizedUsername = normalizedUsername,

                PasswordHash = hashRes.Hash,
                PasswordSalt = hashRes.Salt,
                KdfAlgorithm = hashRes.KdfAlgorithm,
                Prf = hashRes.Prf,
                Iterations = hashRes.Iterations,

                SecurityQuestion = (SecurityQuestion)request.SecurityQuestion,
                SecurityAnswerHash = secAns.Hash,
                SecurityAnswerSalt = secAns.Salt,


                TwoFactorEnabled = false,
                TwoFactorSecret = totpSecret,

                IsEmailConfirmed = false,

            };

            _db.Users.Add(user);
            try
            {
                await _db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException)
            {
                return Conflict(new { message = "Email lub nazwa użytkownika jest już zajęta." });
            }

            var oldTokens = await _db.UserTokens
                .Where(t => t.UserId == user.Id
             && t.UserTokenType == UserTokenType.EmailConfirmation
             && t.ConsumedAt == null)
                .ToListAsync(ct);
            _db.UserTokens.RemoveRange(oldTokens);

            var (code, hash) = EmailVerification.NewCode();

            var now = DateTimeOffset.UtcNow;

            var clientIp = GetClientIp();

            _db.UserTokens.Add(new UserToken
            {
                UserId = user.Id,
                UserTokenType = UserTokenType.EmailConfirmation,
                ValueHash = hash,
                CreatedAt = now,
                ExpiresAt = now.AddMinutes(15),

                RequestIp = clientIp?.ToString(),
            });

            SaveDevEmail(
            user.Email,
            "Potwierdzenie adresu e-mail",
            $"Twój kod potwierdzenia to: <b>{code}</b><br/>Kod wygaśnie o {now.AddMinutes(15):HH:mm}.",
            now.AddMinutes(15));

            await _db.SaveChangesAsync(ct);
            
            var resp = new RegisterResponse
            {
                Id = user.Id,
                Email = user.Email,
                Username = user.Username,
                CreatedAt = user.CreatedAt,
                IsEmailConfirmed = user.IsEmailConfirmed,
                SecurityQuestion = (int)user.SecurityQuestion
            };

            return Created(string.Empty, resp);
        }

        [HttpPost("login")]
        [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken ct)
        {
            var id = (request.Identifier ?? string.Empty).Trim();

            User? user = null;
            if (id.Contains('@'))
            {
                var normalizedEmail = Normalization.NormalizeEmail(id);
                user = await _db.Users.SingleOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, ct);
            }
            else
            {
                var normalizedUsername = Normalization.NormalizeUsername(id);
                user = await _db.Users.SingleOrDefaultAsync(u => u.NormalizedUsername == normalizedUsername, ct);
            }

            if (user is null)
            {
                await Task.Delay(200, ct);
                return Unauthorized(new { message = "Nieprawidłowe dane logowania." });
            }
            if (!user.IsEmailConfirmed)
            {
                return Unauthorized(new
                {
                    message = "Potwierdź adres email, zanim się zalogujesz.",
                    next = new
                    {
                        confirm = "POST /api/auth/confirm-email",
                        resend = "POST /api/auth/resend-confirmation"
                    }
                });
            }

            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow)
                return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Konto tymczasowo zablokowane. Spróbuj ponownie później." });

            var ok = _passwordHasher.Verify(
                request.Password,
                user.PasswordSalt,
                user.Prf,
                user.Iterations,
                user.KdfAlgorithm,
                user.PasswordHash);

            if (!ok)
            {
                user.FailedLoginCount += 1;
                if (user.FailedLoginCount >= MaxFailedLogin)
                {
                    user.LockoutEnd = DateTimeOffset.UtcNow.Add(LockoutDuration);
                    user.FailedLoginCount = 0;
                }

                await _db.SaveChangesAsync(ct);
                await Task.Delay(200, ct);
                return Unauthorized(new { message = "Nieprawidłowe dane logowania." });
            }


            user.FailedLoginCount = 0;
            user.LockoutEnd = null;

            if (_passwordHasher.NeedsRehash(user.Prf, user.Iterations))
            {
                var re = _passwordHasher.ComputeHash(request.Password);
                user.PasswordHash = re.Hash;
                user.PasswordSalt = re.Salt;
                user.Prf = re.Prf;
                user.Iterations = re.Iterations;
                user.KdfAlgorithm = re.KdfAlgorithm;
            }

            if (user.TwoFactorEnabled)
            {
                if (string.IsNullOrWhiteSpace(request.TwoFactorCode))
                {
                    return Unauthorized(new { message = "Wymagany kod 2FA (TOTP). Podaj twoFactorCode (6 cyfr)." });
                }
                if (!_totp.VerifyCode(user.TwoFactorSecret, request.TwoFactorCode, allowedDriftSteps: 0))
                {
                    await Task.Delay(200, ct);
                    return Unauthorized(new { message = "Nieprawidłowy kod 2FA." });
                }
            }

            await _db.SaveChangesAsync(ct);

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.Email, user.Email)
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            var authProps = new AuthenticationProperties();

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProps);

            var resp = new LoginResponse
            {
                UserId = user.Id,
                Email = user.Email,
                Username = user.Username,
                ExpiresAt = authProps.ExpiresUtc
            };

            return Ok(resp);
        }

        [Authorize]
        [HttpPost("logout")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return NoContent();
        }

        [HttpPost("confirm-email")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request, CancellationToken ct)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var normalizedEmail = Normalization.NormalizeEmail(request.Email);
            var user = await _db.Users.SingleOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, ct);
            if (user is null)
                return NotFound(new { message = "Użytkownik nie istnieje." });

            if (user.IsEmailConfirmed)
                return Ok(new
                {
                    message = "Email był już potwierdzony.",
                    next = new { login = "POST /api/auth/login" }
                });

            var now = DateTimeOffset.UtcNow;

            var recentToken = await _db.UserTokens
                .Where(t => t.UserId == user.Id && t.UserTokenType == UserTokenType.EmailConfirmation && t.ConsumedAt == null)
                .OrderByDescending(t => t.CreatedAt)
                .FirstOrDefaultAsync(ct);

            if (recentToken is null)
                return BadRequest(new
                {
                    message = "Brak aktywnego kodu.",
                    next = new { resend = "POST /api/auth/resend-confirmation" }
                });

            if (recentToken.ExpiresAt <= now)
                return BadRequest(new
                {
                    message = "Kod wygasł.",
                    reason = "expired",
                    next = new { resend = "POST /api/auth/resend-confirmation" }
                });

            var hash = EmailVerification.Sha256(request.Code);
            var match = await _db.UserTokens.SingleOrDefaultAsync(t =>
                t.UserId == user.Id
                && t.UserTokenType == UserTokenType.EmailConfirmation
                && t.ConsumedAt == null
                && t.ExpiresAt > now
                && t.ValueHash == hash, ct);

            if (match is null)
                return BadRequest(new
                {
                    message = "Kod nieprawidłowy.",
                    reason = "invalid",
                    hint = "Sprawdź czy nie ma literówki; kod jest jednorazowy.",
                    next = new { resend = "POST /api/auth/resend-confirmation" }
                });

            user.IsEmailConfirmed = true;
            match.ConsumedAt = now;
            await _db.SaveChangesAsync(ct);

            return Ok(new
            {
                message = "Email został potwierdzony.",
                email = user.Email,
                confirmedAt = now,
                next = new { login = "POST /api/auth/login" }
            });
        }

        [HttpPost("resend-confirmation")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
        public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationRequest request, CancellationToken ct)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var normalizedEmail = Normalization.NormalizeEmail(request.Email);
            var user = await _db.Users.SingleOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, ct);
            if (user is null)
                return NotFound(new { message = "Użytkownik nie istnieje." });

            if (user.IsEmailConfirmed)
                return Ok(new
                {
                    message = "Email jest już potwierdzony.",
                    next = new { login = "POST /api/auth/login" }
                });

            var now = DateTimeOffset.UtcNow;

            var lastToken = await _db.UserTokens
                .Where(t => t.UserId == user.Id && t.UserTokenType == UserTokenType.EmailConfirmation && t.ConsumedAt == null)
                .OrderByDescending(t => t.CreatedAt)
                .FirstOrDefaultAsync(ct);

            if (lastToken is not null)
            {
                var secondsSince = (now - lastToken.CreatedAt).TotalSeconds;
                if (secondsSince < 60)
                {
                    var wait = (int)Math.Ceiling(60 - secondsSince);
                    return StatusCode(StatusCodes.Status429TooManyRequests, new
                    {
                        message = "Za często prosisz o kod. Spróbuj ponownie za chwilę.",
                        retryInSeconds = wait
                    });
                }

                _db.UserTokens.RemoveRange(
                    _db.UserTokens.Where(t => t.UserId == user.Id && t.UserTokenType == UserTokenType.EmailConfirmation && t.ConsumedAt == null));
            }

            var (code, hash) = EmailVerification.NewCode();

            var clientIp = GetClientIp();
            var ua = HttpContext.Request.Headers.UserAgent.ToString();

            var newToken = new UserToken
            {
                UserId = user.Id,
                UserTokenType = UserTokenType.EmailConfirmation,
                ValueHash = hash,
                CreatedAt = now,
                ExpiresAt = now.AddMinutes(15),

                RequestIp = clientIp?.ToString()
            };
            _db.UserTokens.Add(newToken);
            SaveDevEmail(
                 user.Email,
                 "Nowy kod potwierdzenia",
                 $"Twój nowy kod to: <b>{code}</b><br/>Ważny do {now.AddMinutes(15):HH:mm}.",
                 now.AddMinutes(15));

            await _db.SaveChangesAsync(ct);

            return Ok(new
            {
                message = "Nowy kod został wysłany.",
                email = user.Email,
                expiresInSeconds = 15 * 60
            });
        }

        [HttpPost("password-reset/request")]
        public async Task<IActionResult> PasswordResetRequest([FromBody] PasswordResetRequest request, CancellationToken ct)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);


            var normalizedEmail = Normalization.NormalizeEmail(request.Email);
            var user = await _db.Users.SingleOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, ct);
            if (user is null)
            {

                await Task.Delay(150, ct);
                return Ok(new PasswordResetRequestResponse { Message = "Jeśli konto istnieje, wysłaliśmy instrukcje.", ExpiresInSeconds = 15 * 60 });
            }

            var old = await _db.UserTokens.Where(t => t.UserId == user.Id && t.UserTokenType == UserTokenType.PasswordReset && t.ConsumedAt == null).ToListAsync(ct);
            _db.UserTokens.RemoveRange(old);

            var (code, hash) = EmailVerification.NewCode();
            var now = DateTimeOffset.UtcNow;
            var clientIp = GetClientIp();

            _db.UserTokens.Add(new UserToken
            {
                UserId = user.Id,
                UserTokenType = UserTokenType.PasswordReset,
                ValueHash = hash,
                CreatedAt = now,
                ExpiresAt = now.AddMinutes(15),
                RequestIp = clientIp?.ToString()
            });

            SaveDevEmail(
            user.Email,
            "Reset hasła",
            $"Kod resetu: <b>{code}</b><br/>Ważny do {now.AddMinutes(15):HH:mm}.",
            now.AddMinutes(15));

            await _db.SaveChangesAsync(ct);

            return Ok(new PasswordResetRequestResponse
            {
                SecurityQuestion = (int)user.SecurityQuestion,
                ExpiresInSeconds = 15 * 60,
                Message = "Podaj odpowiedź na pytanie kontrolne."
            });
        }

        [HttpPost("password-reset/confirm")]
        public async Task<IActionResult> PasswordResetConfirm([FromBody] PasswordResetConfirmRequest request, CancellationToken ct)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var normalizedEmail = Normalization.NormalizeEmail(request.Email);
            var user = await _db.Users.SingleOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail, ct);
            if (user is null) return BadRequest(new { message = "Nieprawidłowe dane." });

            var now = DateTimeOffset.UtcNow;

            var codeHash = EmailVerification.Sha256(request.Code);
            var token = await _db.UserTokens.SingleOrDefaultAsync(t =>
            t.UserId == user.Id &&
            t.UserTokenType == UserTokenType.PasswordReset &&
            t.ConsumedAt == null &&
            t.ExpiresAt > now &&
            t.ValueHash == codeHash, ct);

            if (token is null) return BadRequest(new { message = "Kod resetu nieprawidłowy lub wygasł." });

            var okAns = _passwordHasher.Verify(
            request.SecurityAnswer,
            user.SecurityAnswerSalt,
            user.Prf,
            user.Iterations,
            user.KdfAlgorithm,
            user.SecurityAnswerHash);

            if (!okAns)
            {
                await Task.Delay(200, ct);
                return BadRequest(new { message = "Nieprawidłowa odpowiedź na pytanie kontrolne." });
            }

            var newHash = _passwordHasher.ComputeHash(request.NewPassword);
            user.PasswordHash = newHash.Hash;
            user.PasswordSalt = newHash.Salt;
            user.Prf = newHash.Prf;
            user.Iterations = newHash.Iterations;
            user.KdfAlgorithm = newHash.KdfAlgorithm;

            token.ConsumedAt = now;

            await _db.SaveChangesAsync(ct);

            return Ok(new { message = "Hasło zostało zresetowane. Możesz się zalogować." });
        }
        private IPAddress? GetClientIp()
        {
            var h = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            var first = h?.Split(',').FirstOrDefault()?.Trim();
            if (!string.IsNullOrWhiteSpace(first) && IPAddress.TryParse(first, out var fwd))
                return fwd;

            return HttpContext.Connection.RemoteIpAddress;
        }

        private void SaveDevEmail(string toEmail, string subject, string body, DateTimeOffset expiresAt)
        {
            var normalized = Normalization.NormalizeEmail(toEmail);
            _db.DevEmails.Add(new DevEmailMessage
            {
                ToEmail = toEmail,
                ToNormalizedEmail = normalized,
                Subject = subject,
                Body = body,
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = expiresAt,
            });
        }

        [Authorize]
        [HttpGet("twofactor")]
        public async Task<IActionResult> GetTwoFactor(CancellationToken ct)
        {
            var idStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(idStr, out var uid)) return Unauthorized();

            var user = await _db.Users.AsNoTracking()
                .SingleOrDefaultAsync(u => u.Id == uid, ct);
            if (user is null) return Unauthorized();

            return Ok(new { twoFactorEnabled = user.TwoFactorEnabled });
        }
        public sealed class SetTwoFactorRequest { public bool Enabled { get; set; } }

        [Authorize]
        [HttpPost("twofactor")]
        public async Task<IActionResult> SetTwoFactor([FromBody] SetTwoFactorRequest req, CancellationToken ct)
        {
            var idStr = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(idStr, out var uid)) return Unauthorized();

            var user = await _db.Users.SingleOrDefaultAsync(u => u.Id == uid, ct);
            if (user is null) return Unauthorized();

            if (req.Enabled && (user.TwoFactorSecret == null || user.TwoFactorSecret.Length == 0))
                user.TwoFactorSecret = RandomNumberGenerator.GetBytes(20);

            user.TwoFactorEnabled = req.Enabled;
            await _db.SaveChangesAsync(ct);

            return Ok(new { twoFactorEnabled = user.TwoFactorEnabled });
        }

        [HttpPost("passwordless/request")]
        [ProducesResponseType(typeof(PasswordlessLoginStartResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
        public async Task<IActionResult> PasswordlessLoginStart([FromBody] PasswordlessLoginStartRequest request, CancellationToken ct)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var id = (request.Identifier ?? string.Empty).Trim();
            User? user = id.Contains('@')
                ? await _db.Users.SingleOrDefaultAsync(u => u.NormalizedEmail == Normalization.NormalizeEmail(id), ct)
                : await _db.Users.SingleOrDefaultAsync(u => u.NormalizedUsername == Normalization.NormalizeUsername(id), ct);

            if (user is null)
            {
                await Task.Delay(150, ct);
                return Ok(new PasswordlessLoginStartResponse
                {
                    Message = "Jeśli konto istnieje, wysłaliśmy kod jednorazowy.",
                    ExpiresInSeconds = 15 * 60,
                    SecurityQuestion = null
                });
            }

            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow)
            {
                return StatusCode(StatusCodes.Status429TooManyRequests, new
                {
                    message = "Konto tymczasowo zablokowane. Spróbuj ponownie później."
                });
            }

            if (!user.IsEmailConfirmed)
            {
                return Ok(new PasswordlessLoginStartResponse
                {
                    Message = "Najpierw potwierdź adres e-mail.",
                    ExpiresInSeconds = 0,
                    SecurityQuestion = (int)user.SecurityQuestion
                });
            }

            var now = DateTimeOffset.UtcNow;

            var recent = await _db.UserTokens
                .Where(t => t.UserId == user.Id && t.UserTokenType == UserTokenType.PasswordlessLogin && t.ConsumedAt == null)
                .OrderByDescending(t => t.CreatedAt)
                .FirstOrDefaultAsync(ct);

            if (recent is not null)
            {
                var seconds = (now - recent.CreatedAt).TotalSeconds;
                if (seconds < 60)
                {
                    return StatusCode(StatusCodes.Status429TooManyRequests, new
                    {
                        message = "Za często prosisz o kod. Spróbuj za chwilę.",
                        retryInSeconds = (int)Math.Ceiling(60 - seconds)
                    });
                }

                _db.UserTokens.RemoveRange(_db.UserTokens.Where(t =>
                    t.UserId == user.Id && t.UserTokenType == UserTokenType.PasswordlessLogin && t.ConsumedAt == null));
            }

            var (code, hash) = EmailVerification.NewCode();
            var clientIp = GetClientIp();

            _db.UserTokens.Add(new UserToken
            {
                UserId = user.Id,
                UserTokenType = UserTokenType.PasswordlessLogin,
                ValueHash = hash,
                CreatedAt = now,
                ExpiresAt = now.AddMinutes(15),
                RequestIp = clientIp?.ToString()
            });

            SaveDevEmail(
                user.Email,
                "Jednorazowy kod logowania",
                $"Twój kod: <b>{code}</b><br/>Ważny do {now.AddMinutes(15):HH:mm}.",
                now.AddMinutes(15));

            await _db.SaveChangesAsync(ct);

            return Ok(new PasswordlessLoginStartResponse
            {
                Message = "Kod został wysłany. Podaj odpowiedź na pytanie i kod.",
                ExpiresInSeconds = 15 * 60,
                SecurityQuestion = (int)user.SecurityQuestion
            });
        }

        [HttpPost("passwordless/confirm")]
        [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> PasswordlessLoginConfirm([FromBody] PasswordlessLoginConfirmRequest request, CancellationToken ct)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var id = (request.Identifier ?? string.Empty).Trim();
            User? user = id.Contains('@')
                ? await _db.Users.SingleOrDefaultAsync(u => u.NormalizedEmail == Normalization.NormalizeEmail(id), ct)
                : await _db.Users.SingleOrDefaultAsync(u => u.NormalizedUsername == Normalization.NormalizeUsername(id), ct);

            if (user is null)
            {
                await Task.Delay(200, ct);
                return Unauthorized(new { message = "Nieprawidłowe dane." });
            }

            if (!user.IsEmailConfirmed)
                return BadRequest(new { message = "Najpierw potwierdź adres e-mail." });

            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTimeOffset.UtcNow)
            {
                return StatusCode(StatusCodes.Status429TooManyRequests, new { message = "Konto tymczasowo zablokowane. Spróbuj ponownie później." });
            }

            var now = DateTimeOffset.UtcNow;

            var codeHash = EmailVerification.Sha256(request.Code);
            var token = await _db.UserTokens.SingleOrDefaultAsync(t =>
                t.UserId == user.Id &&
                t.UserTokenType == UserTokenType.PasswordlessLogin &&
                t.ConsumedAt == null &&
                t.ExpiresAt > now &&
                t.ValueHash == codeHash, ct);

            if (token is null)
            {
                user.FailedLoginCount += 1;
                if (user.FailedLoginCount >= MaxFailedLogin)
                {
                    user.LockoutEnd = DateTimeOffset.UtcNow.Add(LockoutDuration);
                    user.FailedLoginCount = 0;
                }
                await _db.SaveChangesAsync(ct);

                await Task.Delay(200, ct);
                return BadRequest(new { message = "Kod nieprawidłowy lub wygasł." });
            }

            var okAns = _passwordHasher.Verify(
                request.SecurityAnswer,
                user.SecurityAnswerSalt,
                user.Prf,
                user.Iterations,
                user.KdfAlgorithm,
                user.SecurityAnswerHash);

            if (!okAns)
            {
                user.FailedLoginCount += 1;
                if (user.FailedLoginCount >= MaxFailedLogin)
                {
                    user.LockoutEnd = DateTimeOffset.UtcNow.Add(LockoutDuration);
                    user.FailedLoginCount = 0;
                }
                await _db.SaveChangesAsync(ct);

                await Task.Delay(200, ct);
                return BadRequest(new { message = "Nieprawidłowa odpowiedź na pytanie kontrolne." });
            }

            if (user.TwoFactorEnabled)
            {
                if (string.IsNullOrWhiteSpace(request.TwoFactorCode))
                {
                    user.FailedLoginCount += 1;
                    if (user.FailedLoginCount >= MaxFailedLogin)
                    {
                        user.LockoutEnd = DateTimeOffset.UtcNow.Add(LockoutDuration);
                        user.FailedLoginCount = 0;
                    }
                    await _db.SaveChangesAsync(ct);

                    return Unauthorized(new { message = "Wymagany kod 2FA (TOTP). Podaj twoFactorCode (6 cyfr)." });
                }

                if (!_totp.VerifyCode(user.TwoFactorSecret, request.TwoFactorCode, allowedDriftSteps: 0))
                {
                    user.FailedLoginCount += 1;
                    if (user.FailedLoginCount >= MaxFailedLogin)
                    {
                        user.LockoutEnd = DateTimeOffset.UtcNow.Add(LockoutDuration);
                        user.FailedLoginCount = 0;
                    }
                    await _db.SaveChangesAsync(ct);

                    await Task.Delay(200, ct);
                    return Unauthorized(new { message = "Nieprawidłowy kod 2FA." });
                }
            }

            user.FailedLoginCount = 0;
            user.LockoutEnd = null;
            token.ConsumedAt = now;

            await _db.SaveChangesAsync(ct);

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Name, user.Username),
                new(ClaimTypes.Email, user.Email)
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);
            var authProps = new AuthenticationProperties();

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, authProps);

            return Ok(new LoginResponse
            {
                UserId = user.Id,
                Email = user.Email,
                Username = user.Username,
                ExpiresAt = authProps.ExpiresUtc
            });
        }

    }
}
