using System.Net;

namespace JwtTestApi.Models.Profile;

public class ProfileUnauthorisedResponse
{
    public HttpStatusCode StatusCode { get; } = HttpStatusCode.Unauthorized;
    public string Message { get; }
    
    public ProfileUnauthorisedResponse(string message)
    {
        Message = message;
    }
}