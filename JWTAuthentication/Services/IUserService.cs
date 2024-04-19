using JWTAuthentication.Models;

namespace JWTAuthentication.Services;

public interface IUserService
{
    Task<User> RegisterAsync(User user);
    Task<User> GetUserByIdAsync(int userId);
    Task<User> GetUserByUsernameAsync(string username);
    string GetClaims();
}
