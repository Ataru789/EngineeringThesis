using EngineeringThesis.Data;
using EngineeringThesis.Services.Common;
using EngineeringThesis.Services.Security;
using EngineeringThesis.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Runtime.InteropServices;
public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly AppDbContext _db;
    private readonly ITotpService _totp;

    public HomeController(ILogger<HomeController> logger, AppDbContext db, ITotpService totp)
    {
        _logger = logger;
        _db = db;
        _totp = totp;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Register()
    {
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }
    public IActionResult Login()
    {
        return View();
    }

    public IActionResult Profile()
    {
        return View();
    }

    public IActionResult PasswordlessLogin()
    {
        return View(); 
    }

    public IActionResult Mailbox()
    {
        return View();
    }

    public IActionResult Totp()
    {
        return View();
    }

    [HttpGet]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public async Task<IActionResult> Mailbox(string? email, CancellationToken ct)
    {

        if (string.IsNullOrWhiteSpace(email))
            return View(new List<DevEmailMessage>());

        var normalized = Normalization.NormalizeEmail(email);
        var exists = await _db.Users.AsNoTracking()
            .AnyAsync(u => u.NormalizedEmail == normalized, ct);

        if (!exists)
        {
            ModelState.AddModelError("Email", "U¿ytkownik z takim e-mailem nie istnieje.");
            return View(new List<DevEmailMessage>());
        }

        var messages = await _db.DevEmails.AsNoTracking()
            .Where(m => m.ToNormalizedEmail == normalized)
            .OrderByDescending(m => m.CreatedAt)
            .ToListAsync(ct);

        return View(messages);
    }

    [HttpGet]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public async Task<IActionResult> Totp(string? email, CancellationToken ct)
    {

        if (string.IsNullOrWhiteSpace(email))
            return View();

        var normalized = Normalization.NormalizeEmail(email);
        var exists = await _db.Users.AsNoTracking()
            .AnyAsync(u => u.NormalizedEmail == normalized, ct);

        if (!exists)
        {
            ModelState.AddModelError("Email", "U¿ytkownik z takim e-mailem nie istnieje.");
            return View();
        }

        return View();
    }

    [HttpGet]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public async Task<IActionResult> TotpData([FromQuery] string email, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(email))
            return BadRequest(new { message = "Brak e-maila." });

        var normalized = Normalization.NormalizeEmail(email);
        var user = await _db.Users.AsNoTracking()
            .SingleOrDefaultAsync(u => u.NormalizedEmail == normalized, ct);

        if (user is null)
            return NotFound(new { message = "Nie znaleziono u¿ytkownika." });

        var code = _totp.GenerateCode(user.TwoFactorSecret);
        var validFor = _totp.SecondsUntilNextStep();

        var nowUtc = DateTimeOffset.UtcNow;
        var expiresUtc = nowUtc.AddSeconds(validFor);

        var tzId = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "Central European Standard Time"
            : "Europe/Warsaw";
        var plTz = TimeZoneInfo.FindSystemTimeZoneById(tzId);
        var expiresLocal = TimeZoneInfo.ConvertTime(expiresUtc, plTz).ToString("yyyy-MM-dd HH:mm:ss");

        return Json(new
        {
            code,
            validForSeconds = validFor,
            expiresAtLocal = expiresLocal
        });
    }
}
