using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using AuthTest.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;

namespace AuthTest.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [Authorize]
    [Route("privacy")]
    public IActionResult Privacy()
    {
        return View();
    }

    [HttpGet]
    [Route("login")]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login(User model)
    {
        if (ModelState.IsValid)
        {
            if (AuthenticateUser(model.Name, model.Password))
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, model.Name),
                    // Другие утверждения, если необходимо
                };

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                return RedirectToAction("Privacy", "Home");
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        }

        return View(model);
    }

    public bool AuthenticateUser(string username, string password)
    {
        var users = new List<User>
        {
            new User { Name = "admin", Password = "admin" },
            new User { Name = "user", Password = "123" },
        };

        var user = users.FirstOrDefault(u => u.Name == username & u.Password == password);

        if (user != null && user.Password == password)
        {
            return true; // Пользователь успешно аутентифицирован.
        }

        return false; // Пользователь не найден или пароль неверный.
    }
}