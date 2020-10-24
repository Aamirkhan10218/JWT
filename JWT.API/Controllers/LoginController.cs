using JWT.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT.API.Controllers
{
    [Authorize]
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public LoginController(IConfiguration configuration)
        {
            this._configuration = configuration;
        }
        [AllowAnonymous]
        [HttpGet]
        public IActionResult UserLogin(string userName, string password)
        {
            UserModel user = new UserModel();
            user.UserName = userName;
            user.Password = password;
            IActionResult response = Unauthorized();
            var result = AuthenticateUser(user);
            if (result != null)
            {
                var tokenString = generateJSONWebToke(result);
                response = Ok(new { token = tokenString });
            }
            return response;
        }

       
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("I am Aamir Khan");
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            var user = new UserModel();
            if (login.UserName == "AamirKhan" && login.Password == "Allah")
            {
               user = new UserModel { UserName = "Aamir Khan", Email = "AamirKhan@Example.com", Password = "Allah", Role = "Admin" };
            }
            return user;
        }
        private string generateJSONWebToke(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role,user.Role)
            };
            var token = new JwtSecurityToken
                (
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddDays(20),
                signingCredentials: credentials
                );
            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodedToken;
        }
    }
}
