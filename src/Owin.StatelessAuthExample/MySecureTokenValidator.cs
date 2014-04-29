namespace Owin.StatelessAuthExample
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using JWT;
    using RequiresStatelessAuth;
    using System.Security.Claims;

    public class MySecureTokenValidator : ITokenValidator
    {
        private readonly IConfigProvider configProvider;

        public MySecureTokenValidator(IConfigProvider configProvider)
        {
            this.configProvider = configProvider;
        }

        public ClaimsPrincipal ValidateUser(string token)
        {
            try
            {
                //Claims don't deserialize :(
                //var jwttoken = JsonWebToken.DecodeToObject<JwtToken>(token, configProvider.GetAppSetting("securekey"));
                
                var decodedtoken = JsonWebToken.DecodeToObject(token, configProvider.GetAppSetting("securekey")) as Dictionary<string, object>;

                var jwttoken = new JwtToken()
                {
                    Audience = (string)decodedtoken["Audience"],
                    Issuer = (string)decodedtoken["Issuer"],
                    Expiry = DateTime.Parse(decodedtoken["Expiry"].ToString()),
                };

                if (decodedtoken.ContainsKey("Claims"))
                {
                    var claims = new List<Claim>();

                    for (int i = 0; i < ((ArrayList)decodedtoken["Claims"]).Count; i++)
                    {
                        var type = ((Dictionary<string, object>)((ArrayList)decodedtoken["Claims"])[i])["Type"].ToString();
                        var value = ((Dictionary<string, object>)((ArrayList)decodedtoken["Claims"])[i])["Value"].ToString();
                        claims.Add(new Claim(type, value));
                    }

                    jwttoken.Claims = claims;
                }

                if (jwttoken.Expiry < DateTime.UtcNow)
                {
                    return null;
                }

                return new ClaimsPrincipal(new ClaimsIdentity(jwttoken.Claims, "Token"));
            }
            catch (SignatureVerificationException)
            {
                return null;
            }
        }
    }
}
