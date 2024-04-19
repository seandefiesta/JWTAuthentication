using JWTAuthentication.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using JWTAuthentication.Services;
using JWTAuthentication.Repository;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public AuthController(IConfiguration configuration, IUserService userService, IRefreshTokenRepository refreshTokenRepository)
        {
            _configuration = configuration;
            _userService = userService;
            _refreshTokenRepository = refreshTokenRepository;
        }

        [HttpGet, Authorize(Roles = "Admin")]
        public ActionResult<string> GetClaims()
        {
            return Ok(_userService.GetClaims());
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserResponseDto req)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(req.Password);

            var user = new User
            {
                Username = req.Username,
                PasswordHash = passwordHash
            };

            await _userService.RegisterAsync(user);
            string token = CreateToken(user);

            return Ok(token);
        }

        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserResponseDto req)
        {
            var user = await _userService.GetUserByUsernameAsync(req.Username);

            if (user == null)
            {
                return BadRequest("Wrong username");
            }

            if (!BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
            {
                return BadRequest("Wrong password");
            }

            var refreshToken = GenerateRefreshToken();
            await _refreshTokenRepository.AddAsync(refreshToken);

            string token = CreateToken(user);

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            var refreshToken = request.RefreshToken;

            var storedRefreshToken = await _refreshTokenRepository.GetByTokenAsync(refreshToken);
            if (storedRefreshToken == null || storedRefreshToken.Expires < DateTime.UtcNow)
            {
                return Unauthorized("Invalid or expired refresh token");
            }

            var user = await _userService.GetUserByIdAsync(storedRefreshToken.UserId);
            if (user == null)
            {
                return Unauthorized("User not found.");
            }

            var newToken = CreateToken(user);
            return Ok(newToken);
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            { 
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddMinutes(3),
                Created = DateTime.UtcNow
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires,
            };

            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires = newRefreshToken.Expires;
        }

        //JWT TOKEN
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim("user_id", user.Id.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(5),
                    signingCredentials: creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
