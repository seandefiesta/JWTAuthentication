using JWTAuthentication.Database;
using JWTAuthentication.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace JWTAuthentication.Services;

public class UserService : IUserService
{
    private readonly Data _dbContext;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserService(Data dbContext, IHttpContextAccessor httpContextAccessor)
    {
        _dbContext = dbContext;
        _httpContextAccessor = httpContextAccessor;
    }

    public string GetClaims()
    {
        var result = string.Empty;
        if (_httpContextAccessor.HttpContext is not null)
        {
            var userName = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            var userRole = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Role);

            result = $"Username:{userName}, Role:{userRole}";
        }
        return result;
    }

    public async Task<User> GetUserByUsernameAsync(string username)
    {
        return await _dbContext.Users.FirstOrDefaultAsync(x => x.Username == username);
    }

    public async Task<User> GetUserByIdAsync(int userId)
    {
        return await _dbContext.Users.FindAsync(userId);
    }

    public async Task<User> RegisterAsync(User user)
    {
        if(await _dbContext.Users.AnyAsync(x => x.Username == user.Username))
        {
            throw new InvalidOperationException("User with this username already exist");
        }

        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        return user;
    }
}
