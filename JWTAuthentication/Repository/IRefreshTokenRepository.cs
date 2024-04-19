using JWTAuthentication.Models;

namespace JWTAuthentication.Repository
{
    public interface IRefreshTokenRepository
    {
        Task<RefreshToken> GetByTokenAsync(string token);
        Task AddAsync(RefreshToken refeshToken);
        Task UpdateAsync(RefreshToken refeshToken);
        Task RemoveAsync(RefreshToken refeshToken);
    }
}
