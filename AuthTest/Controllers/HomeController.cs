using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using AuthTest.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace AuthTest.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    //[Authorize]
    //[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    [Route("privacy")]
    public IActionResult Privacy()
    {
        //return View();
       if (User.Identity.IsAuthenticated)
       {
           return View();
       }

       return RedirectToAction("Login");
    }

    [HttpGet]
    [Route("login")]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [Route("login")]
    public IActionResult Login(User model)
    {
        if (AuthenticateUser(model.Name, model.Password))
        {
            var token = GenerateToken(model.Name);
            Response.Cookies.Append("token", token);
            return RedirectToAction("Privacy");
        }
        else
        {
            ModelState.AddModelError("", "Неправильный логин или пароль");
            return View("Login", model);
        }
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

    public string GenerateToken(string username)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("my_secret_long_key"));

        var token = new JwtSecurityToken(
            issuer: "a",
            audience: "b",
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(3),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}