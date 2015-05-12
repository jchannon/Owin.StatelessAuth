namespace Owin.StatelessAuth
{
    using Minimatch;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;

    public class StatelessAuth
    {
        private readonly ITokenValidator tokenValidator;
        private readonly StatelessAuthOptions statelessAuthOptions;
        private readonly Func<IDictionary<string, object>, Task> nextFunc;
        private const string ServerUser = "server.User";

        public StatelessAuth(Func<IDictionary<string, object>, Task> nextFunc, ITokenValidator tokenValidator, StatelessAuthOptions statelessAuthOptions)
        {
            this.nextFunc = nextFunc;
            this.tokenValidator = tokenValidator;
            this.statelessAuthOptions = statelessAuthOptions;
        }

        public Task Invoke(IDictionary<string, object> environment)
        {
            if (!environment.ContainsKey("owin.RequestPath"))
            {
                throw new ApplicationException("Invalid OWIN request. Expected owin.RequestPath, but not present.");
            }

            var path = Uri.UnescapeDataString((string)environment["owin.RequestPath"]);

            if (statelessAuthOptions != null && statelessAuthOptions.IgnorePaths != null)
            {
                foreach (var ignorePath in statelessAuthOptions.IgnorePaths)
                {
                    var mm = new Minimatcher(ignorePath, new Options() { IgnoreCase = true });

                    if (mm.IsMatch(path))
                    {
                        return nextFunc(environment);
                    }
                }
            }

            string token = VerifyAuthorizationHeader(environment);

            if (token == null && statelessAuthOptions.VerifyAuthenticationQueryString)
            {
                token = VerifyAuthorizationQueryString(environment);
            }

            if (token == null)
            {
                return AuthChallengeResponse(environment);
            }

            var validatedUser = tokenValidator.ValidateUser(token);

            if (validatedUser == null)
            {
                return AuthChallengeResponse(environment);
            }

            if (environment.ContainsKey(ServerUser))
            {
                environment[ServerUser] = validatedUser;
            }
            else
            {
                environment.Add(ServerUser, validatedUser);
            }

            return nextFunc(environment);
        }

        private string VerifyAuthorizationHeader(IDictionary<string, object> environment)
        {
            string token = null;
            var requestHeaders = (IDictionary<string, string[]>)environment["owin.RequestHeaders"];
            if (requestHeaders.ContainsKey("Authorization"))
            {
                token = requestHeaders["Authorization"].FirstOrDefault();
                token = (string.IsNullOrEmpty(token) ? null : token);
            }

            return token;
        }

        private string VerifyAuthorizationQueryString(IDictionary<string, object> environment)
        {
            var queryString = environment["owin.RequestQueryString"] as string;
            var query = new UrlEncodingParser(queryString, statelessAuthOptions.DecodePlusSignsAsSpacesQueryString);
            var token = query["Authorization"];
            return (string.IsNullOrEmpty(token) ? null : token);
        }

        private Task AuthChallengeResponse(IDictionary<string, object> environment)
        {
            if (statelessAuthOptions != null && statelessAuthOptions.PassThroughUnauthorizedRequests)
            {
                return nextFunc(environment);
            }

            environment["owin.ResponseStatusCode"] = 401;

            if (statelessAuthOptions != null && !string.IsNullOrWhiteSpace(statelessAuthOptions.WWWAuthenticateChallenge))
            {
                var wwwauthenticatechallenge = statelessAuthOptions.WWWAuthenticateChallenge;

                if (!environment.ContainsKey("owin.ResponseHeaders"))
                {
                    environment.Add("owin.ResponseHeaders", new Dictionary<string, string[]>());
                }

                var responseHeaders = (IDictionary<string, string[]>)environment["owin.ResponseHeaders"];
                responseHeaders.Add("WWW-Authenticate", new[] { wwwauthenticatechallenge });
            }

            return Task.FromResult(0);
        }
    }
}