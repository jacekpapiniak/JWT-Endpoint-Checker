namespace JwtTestApi.Endpoints;

public static class LoginEndpoints
{
    public static IEndpointRouteBuilder MapLoginEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/login", (LoginRequest request) =>
        {
            // In a real application, you would validate the user's credentials here
            if (request.Username == "testuser" && request.Password == "password")
            {
                // Generate a JWT token (this is just a placeholder)
                var token = "fake-jwt-token";
                return Results.Ok(new { Token = token });
            }
            else
            {
                return Results.Unauthorized();
            }
        });

        return app;
    }
}