using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthTest.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthTest.Controllers;

[Route("Token")]
public class TokenController : Controller
{
    [HttpGet]
    [Route("login")]
    public IActionResult Login()
    {
        return View();
    }
    
    [HttpPost]
    [Route("login")]
    public IActionResult Login(LoginViewModel model)
    {
        if (AuthenticateUser(model.Name, model.Password))
        {
            var token = GenerateToken(model.Name);
            Response.Cookies.Append("token", token);
            return RedirectToAction("Privacy", "Home"); 
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
            expires: DateTime.UtcNow.AddHours(1), 
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}