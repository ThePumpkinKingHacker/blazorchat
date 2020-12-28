using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using web.Classes;

namespace web.api
{
    [Route("/api/[controller]")]
    public class LoginController : Controller
    {
        private readonly ILogger<LoginController> _logger;
        private readonly ChatContext _context;
        private readonly IConnectionMultiplexer _connectionMultiplexer;

        public LoginController(ILogger<LoginController> logger, ChatContext context, IConnectionMultiplexer connectionMultiplexer)
        {
            _logger = logger;
            _context = context;
            _connectionMultiplexer = connectionMultiplexer;
        }


        [HttpGet]
        public IActionResult Get()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return Ok();
            }
            else
            {
                return Unauthorized();
            }
        }

        [HttpPost]
        public async Task<IActionResult> Post(LoginModel model)
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
    }
}