namespace Owin.StatelessAuth.Sample
{
    using System;
    using System.Globalization;
    using System.IdentityModel.Tokens;
    using System.Security.Claims;
    using Nancy;
    using Nancy.ModelBinding;
    using Nancy.Security;

    public class HomeModule : NancyModule
    {
        public HomeModule()
        {
            Get["/login"] = _ => View["Login"];

            Post["/login"] = _ =>
            {
                var credentials = this.Bind<Credentials>();

                //Verify user/pass
                if (credentials.User != "fred" && credentials.Password != "securepwd")
                {
                    return 401;
                }

                var identity = new ClaimsIdentity(new[]
                {
                    new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Administrator"),
                    new Claim(ClaimTypes.Name, credentials.User)
                });

                var securityTokenHandler = new JwtSecurityTokenHandler();
                var securityToken = securityTokenHandler.CreateToken(
                    subject: identity,
                    issuer: Startup.Issuer,
                    audience: Startup.Audience,
                    expires: DateTime.UtcNow.AddDays(7),
                    signingCredentials: Startup.Credentials);
                
                return Negotiate.WithModel(securityTokenHandler.WriteToken(securityToken));
            };

            Get["/"] = _ =>
            {
                var principal = Context.GetMSOwinUser();
                if (principal == null || principal.Identity == null || !principal.Identity.IsAuthenticated)
                {
                    return 500;
                }

                var name = principal.FindFirst(ClaimTypes.Name);
                if (name == null)
                {
                    return 500;
                }

                return string.Format(CultureInfo.InvariantCulture, "Hello {0}", name.Value);
            };
        }
    }

    public class Credentials
    {
        public string User { get; set; }

        public string Password { get; set; }
    }
}
