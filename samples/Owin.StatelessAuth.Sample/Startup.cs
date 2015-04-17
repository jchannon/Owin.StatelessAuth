namespace Owin.StatelessAuth.Sample
{
    using System;
    using System.IdentityModel.Tokens;
    using Owin.StatelessAuth.Jwt;

    public class Startup
    {
        internal static readonly string Issuer = "http://issuer.com";
        internal static readonly string Audience = "http://mycoolwebsite.com";

        internal static readonly SecurityKey Key = new InMemorySymmetricSecurityKey(
            Convert.FromBase64String("Srtjyi8wMFfmP9Ub8U2ieVGAcrP/7gK3VM/K6KfJ/fI="));

        internal static readonly SigningCredentials Credentials = new SigningCredentials(Key,
            SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest);

        public void Configuration(IAppBuilder app)
        {
            app.RequiresStatelessAuth(new JwtTokenValidator(Issuer, Audience, Key), new StatelessAuthOptions
            {
                IgnorePaths = new[] { "/login", "/content/*.js" }
            });

            app.UseNancy();
        }
    }
}
