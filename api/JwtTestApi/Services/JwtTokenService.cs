using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtTestApi.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtTestApi.Services;

using JwtTestApi.Common;

public class JwtTokenService
{
    private string _secretKey;
    private string _issuer;
    private string _audience;
    private IConfiguration _config;

    public JwtTokenService(IConfiguration config)
    {
        _config = config;
        _secretKey = _config["Jwt:SecretKey"];
        _issuer = _config["Jwt:Issuer"];
         _audience = _config["Jwt:Audience"];
    }

    public LoginResponse GenerateToken(string email)
    {
        return email switch
        {
            Email.ValidUser => new LoginResponse(CreateToken(email, 10)),
            Email.MalformedUser => CreateMalformedTokenResponse(Email.MalformedUser),
            Email.MisconfiguredUser => new LoginResponse(CreateToken(email, 365 * 24 * 60)), // Expires in 1 year
            Email.InvalidUser => new LoginResponse("Not a Jwt Token"),
            _ => new LoginResponse(string.Empty)
        };
    }

    private LoginResponse CreateMalformedTokenResponse(string email)
    {
        var token = CreateToken(email, 10);
        
        // Corrupt the token by changing a character
        var splitToken= token.Split(".");
        
        //The token is in the format header.payload.signature
        //We remove the dot between the header and payload.
        //I also add some random characters to make it more obviously malformed
        var corruptedToken = $"{splitToken[0]}ab785{splitToken[1]}kj987.{splitToken[2]}aaa";
        
        return new LoginResponse(corruptedToken);
    }

    public string CreateToken(string subject, int expiresInMinutes)
    {
        Claim[] claims =
        [
            new (JwtRegisteredClaimNames.Sub, subject),
            new (JwtRegisteredClaimNames.Email, subject),
            new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        ];

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expiresInMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}