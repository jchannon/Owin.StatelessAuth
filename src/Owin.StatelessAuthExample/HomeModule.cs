namespace Owin.StatelessAuthExample
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using JWT;
    using Nancy;
    using Nancy.ModelBinding;

    public class HomeModule : NancyModule
    {
        public HomeModule(IConfigProvider configProvider, IJwtWrapper jwtWrapper)
        {
            Get["/login"] = _ => View["Login"];

            Post["/login"] = _ =>
            {
                var user = this.Bind<UserCredentials>();
                if (user.User != "fred" && user.Password != "securepwd")
                {
                    return 401;
                }

                var jwttoken = new JwtToken()
                {
                    Issuer = "http://issuer.com",
                    Audience = "http://mycoolwebsite.com",
                    Claims =
                        new List<Claim>(new[]
                        {
                            new Claim(ClaimTypes.Role, "Administrator"),
                            new Claim(ClaimTypes.Name, "Fred")
                        }),
                    Expiry = DateTime.UtcNow.AddDays(7)
                };
                
                var token = jwtWrapper.Encode(jwttoken, configProvider.GetAppSetting("securekey"), JwtHashAlgorithm.HS256);
                return Negotiate.WithModel(token);
            };

            Get["/"] = _ => "Hello Secure World!";
        }
    }

    public class UserCredentials
    {
        public string User { get; set; }
        public string Password { get; set; }
    }

    public interface IJwtWrapper
    {
        string Encode(object payload, string key, JwtHashAlgorithm algorithm);
        //object DecodeToObject(string token, string key, bool verify = true);
    }

    public class JwtWrapper : IJwtWrapper
    {
        public string Encode(object payload, string key, JwtHashAlgorithm algorithm)
        {
            return JsonWebToken.Encode(payload, key, algorithm);
        }
    }
}
