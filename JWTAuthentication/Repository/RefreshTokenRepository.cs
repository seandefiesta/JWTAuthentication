using JWTAuthentication.Database;
using JWTAuthentication.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Repository
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly Data _dbContext;

        public RefreshTokenRepository(Data dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<RefreshToken> GetByTokenAsync(string token)
        {
            return await _dbContext.RefreshTokens.SingleOrDefaultAsync(x => x.Token == token);
        }
        public async Task AddAsync(RefreshToken refeshToken)
        {
            await _dbContext.RefreshTokens.AddAsync(refeshToken);
            await _dbContext.SaveChangesAsync();
        }

        public async Task UpdateAsync(RefreshToken refeshToken)
        {
            _dbContext.RefreshTokens.Update(refeshToken);
            await _dbContext.SaveChangesAsync();
        }
        public async Task RemoveAsync(RefreshToken refeshToken)
        {
            _dbContext.RefreshTokens.Remove(refeshToken);
            await _dbContext.SaveChangesAsync();
        }
    }
}
