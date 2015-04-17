namespace Owin.StatelessAuth.Jwt
{
    using System;
    using System.Security.Claims;
    using System.IdentityModel.Tokens;

    public class JwtTokenValidator : ITokenValidator
    {
        private readonly ISecurityTokenValidator securityTokenValidator;
        private readonly TokenValidationParameters tokenValidationParameters;
        
        public JwtTokenValidator(string issuer, string audience, SecurityKey key)
            : this(new TokenValidationParameters
            {
                ValidAudience = audience,
                ValidIssuer = issuer,
                IssuerSigningKey = key
            }) { }

        public JwtTokenValidator(TokenValidationParameters tokenValidationParameters)
            : this(securityTokenValidator: new JwtSecurityTokenHandler(),
                   tokenValidationParameters: tokenValidationParameters) { }

        public JwtTokenValidator(
            ISecurityTokenValidator securityTokenValidator,
            TokenValidationParameters tokenValidationParameters)
        {
            this.securityTokenValidator = securityTokenValidator;
            this.tokenValidationParameters = tokenValidationParameters;
        }

        public ClaimsPrincipal ValidateUser(string token)
        {
            try
            {
                SecurityToken securityToken;
                return securityTokenValidator.ValidateToken(token, tokenValidationParameters, out securityToken);
            }

            catch
            {
                return null;
            }
        }
    }
}
