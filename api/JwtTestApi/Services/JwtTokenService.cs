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
        
        // To configure JWT token we need to set the secret key, issuer and audience. We read these values from the configuration.
        // In case any of these values are missing, then we throw an exception to inform what is missing to help troubleshooting.
        _secretKey = _config["Jwt:SecretKey"] ?? throw new InvalidOperationException("Jwt:SecretKey missing");
        _issuer = _config["Jwt:Issuer"] ?? throw new InvalidOperationException("Jwt:Issuer missing");
        _audience = _config["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience missing");
    }

    public LoginResponse GenerateToken(string email)
    {
        return email switch
        {
            Email.ValidUser => new LoginResponse(CreateToken(email, 10)),
            Email.MalformedUser => CreateMalformedTokenResponse(Email.MalformedUser),
            Email.ExpiredUser => new LoginResponse(CreateToken(email, -TimeSpan.FromDays(2*365).Minutes)),
            Email.MisconfiguredUser => new LoginResponse(CreateToken(email, TimeSpan.FromDays(2*365).Minutes)),
            Email.InvalidUser => new LoginResponse("Not a Jwt Token"),
            _ => new LoginResponse(string.Empty)
        };
    }

    public async Task<TokenValidationResult> IsValidToken(string? token)
    {
        //1 Validate if the provided token is not null or empty
        if (string.IsNullOrEmpty(token))
        {
            return new TokenValidationResult()
            {
                IsValid = false,
                Exception = new SecurityTokenException("Token is null or empty")
            };
        }
        
        var tokenHandler = new JwtSecurityTokenHandler();
        
        //2 Validate if the provided token is well formatted JWT Token
        if (!tokenHandler.CanReadToken(token))
        {
            return new TokenValidationResult()
            {
                IsValid = false,
                Exception = new SecurityTokenException("Token is not in a valid JWT format")
            };
        }
        
        //3 Validate JWT Token
        var validationResult = await tokenHandler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            
            // Deliberate authentication weakness for controlled testing:
            // lifetime validation is disabled so that expired tokens may still be accepted.
            ValidateLifetime = false, // This makes sure that token expiry time is validated
            
            ValidIssuer = _issuer,
            ValidAudience = _audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey)),
            ClockSkew = TimeSpan.Zero, // This check the lifespan of the token, we set it to zero to make sure that the token is valid only for the exact time specified in the token and not a few minutes more (which is the default behavior)
            RequireExpirationTime = true, // This ensures that the token must have an expiration time, if not it will be rejected
            RequireSignedTokens = true
        });
        
        return validationResult;
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

    private string CreateToken(string subject, int expiresInMinutes)
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