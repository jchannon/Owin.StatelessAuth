using System;
using System.IdentityModel.Tokens;
using Owin.StatelessAuth.Jwt;

namespace Owin.StatelessAuth
{
    public static class JwtAuthExtensions
    {
        public static IAppBuilder RequiresJwtAuth(this IAppBuilder app, string issuer,
            string audience, SecurityKey key, StatelessAuthOptions options = null)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            return app.RequiresStatelessAuth(new JwtTokenValidator(issuer, audience, key), options);
        }
    }
}
