using System.Text.Json;
using JwtTestApi.Common;
using JwtTestApi.Models.Profile;
using JwtTestApi.Services;

namespace JwtTestApi.Endpoints;

public static class ProfileEndpoints
{
    public static IEndpointRouteBuilder MapProfileEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/profile", async (ProfileRequest request, JwtTokenService jwtService) =>
        {
            var result = await jwtService.IsValidToken(request.Token);

            return result.IsValid 
                ? Results.Ok(new ProfileResponse("Valid User", Email.ValidUser, "Student")) 
                : Results.Json(new ProfileUnauthorisedResponse(result.Exception.Message), JsonSerializerOptions.Default, "json", StatusCodes.Status401Unauthorized);
        });

        return app;
    }
}