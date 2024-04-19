using System.Security.Claims;

namespace JWTAuthentication.Services
{
    public interface ITokenService
    {
        ClaimsPrincipal ValidateToken(string token);
        string RefreshToken(string refreshToken);
    }
}
