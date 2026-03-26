using JwtTestApi.Models;
using JwtTestApi.Common;
using JwtTestApi.Services;

namespace JwtTestApi.Endpoints;

public static class LoginEndpoints
{
    public static IEndpointRouteBuilder MapLoginEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/login", (LoginRequest request, JwtTokenService jwtService) =>
        {
            return request switch
            {
                { Email: Email.ValidUser, Password: Email.TestPassword }
                    => Results.Ok(jwtService.GenerateToken(request.Email)),
                
                { Email: Email.MalformedUser, Password: Email.TestPassword }
                    => Results.Ok(jwtService.GenerateToken(request.Email)),
                
                { Email: Email.MisconfiguredUser, Password: Email.TestPassword }
                    => Results.Ok(jwtService.GenerateToken(request.Email)),
                
                { Email: Email.InvalidUser, Password: Email.TestPassword }
                    => Results.Ok(jwtService.GenerateToken(request.Email)),
                _ => Results.Unauthorized()
            };
        });

        return app;
    }
}