using JWTAuthentication.Services;

namespace JWTAuthentication.Middleware
{
    public class TokenRefreshMiddleware
    {
        private readonly RequestDelegate _next;

        public TokenRefreshMiddleware(RequestDelegate next)
        {
            _next = next;
        }

       public async Task Invoke(HttpContext context)
        {
            var tokenService = context.RequestServices.GetRequiredService<ITokenService>();

            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (!string.IsNullOrEmpty(token))
            {
                var principal = tokenService.ValidateToken(token);
                if(principal != null) 
                {
                    await _next(context);
                    return;
                }
            }

            var refreshToken = context.Request.Headers["Refresh-Token"].FirstOrDefault();
            if (!string.IsNullOrEmpty(refreshToken))
            {
                var newToken = tokenService.RefreshToken(refreshToken);
                if (!string.IsNullOrEmpty(newToken))
                {
                    context.Response.Headers.Add("Authorization", "Bearer " + newToken);
                }
            }

            await _next(context);
        }
    }
}
