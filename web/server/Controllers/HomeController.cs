using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using web.Models;
using web.Classes;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using StackExchange.Redis;

namespace web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ChatContext _context;
        private readonly IConnectionMultiplexer _connectionMultiplexer;

        public HomeController(ILogger<HomeController> logger, ChatContext context, IConnectionMultiplexer connectionMultiplexer)
        {
            _logger = logger;
            _context = context;
            _connectionMultiplexer = connectionMultiplexer;
        }

        public IActionResult Index()
        {
            var existingAdmin = _context.Users.FirstOrDefault(m => m.RoleEnum == 0);

            if (existingAdmin == null)
            {
                return RedirectToAction("Index", "Setup");
            }

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Index(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var existingUser = _context.Users.FirstOrDefault(m => m.UserName == model.UserName);

                //Grab current password attempts from redis
                var db = _connectionMultiplexer.GetDatabase();
                var currentCount = db.StringGet(model.UserName, 0);

                if (!string.IsNullOrEmpty(currentCount) && Convert.ToInt32(currentCount) > 5)
                {
                    ModelState.AddModelError("UserName", "Max password attempts has been exceeded.");
                    _logger.LogWarning($"{model.UserName} has been locked out due to excessive login failures.");
                }
                else
                {
                    if (existingUser == null)
                    {
                        ModelState.AddModelError("UserName", "Invalid Username or Password.");
                        _logger.LogWarning($"Invalid username or password for {model.UserName}.");
                    }
                    else
                    {
                        var hashedPassword = PasswordHelper.GenerateSaltedHash(model.Password, existingUser.Salt);
                        if (!PasswordHelper.CompareByteArrays(hashedPassword, existingUser.Password))
                        {
                            ModelState.AddModelError("UserName", "Invalid Username or Password");
                            _logger.LogWarning($"Invalid username or password for {model.UserName}.");
                        }
                    }
                }

                if (ModelState.IsValid)
                {
                    var role = existingUser.RoleEnum == 0 ? "Administrator" : "User";

                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, model.UserName),
                        new Claim(ClaimTypes.Role, role),
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                    var authProperties = new AuthenticationProperties
                    {

                    };

                    _logger.LogWarning($"Successful login for {model.UserName}.");

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties);

                    return RedirectToAction("Index", "Chat");
                }
                else
                {
                    //Increment password attempts and set expiration 5 more minutes
                    db.StringIncrement(model.UserName);
                    db.KeyExpire(model.UserName, new TimeSpan(0, 5, 0));
                }
            }
            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
