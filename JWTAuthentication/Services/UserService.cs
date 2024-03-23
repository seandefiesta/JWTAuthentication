using System.Security.Claims;

namespace JWTAuthentication.Services;

public class UserService : IUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public string GetClaims()
    {
        var result = string.Empty;
        if(_httpContextAccessor.HttpContext is not null)
        {
            var userName = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            var userRole = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Role);

            result = $"Username:{userName}, Role:{userRole}";
        }

        return result;
    }
}
