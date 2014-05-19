namespace Owin.StatelessAuth
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
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

            var path = (string)environment["owin.RequestPath"];

            if (statelessAuthOptions != null && statelessAuthOptions.IgnorePaths.Any(x => path.IndexOf(x, StringComparison.OrdinalIgnoreCase) >= 0))
            {
                return nextFunc(environment);
            }

            var requestHeaders = (IDictionary<string, string[]>)environment["owin.RequestHeaders"];
            if (!requestHeaders.ContainsKey("Authorization"))
            {
                SetResponseStatusCodeAndHeader(environment);
                return ReturnCompletedTask();
            }

            var token = requestHeaders["Authorization"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(token))
            {
                SetResponseStatusCodeAndHeader(environment);
                return ReturnCompletedTask();
            }

            var validatedUser = tokenValidator.ValidateUser(token);

            if (validatedUser == null)
            {
                SetResponseStatusCodeAndHeader(environment);
                return ReturnCompletedTask();
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

        private void SetResponseStatusCodeAndHeader(IDictionary<string, object> environment)
        {
            environment["owin.ResponseStatusCode"] = 401;

            var wwwauthenticatechallenge = "Digest";

            if (statelessAuthOptions != null && !string.IsNullOrWhiteSpace(statelessAuthOptions.WWWAuthenticateChallenge))
            {
                wwwauthenticatechallenge = statelessAuthOptions.WWWAuthenticateChallenge;
            }

            if (!environment.ContainsKey("owin.ResponseHeaders"))
            {
                environment.Add("owin.ResponseHeaders", new Dictionary<string, string[]>());
            }

            var responseHeaders = (IDictionary<string, string[]>)environment["owin.ResponseHeaders"];
            responseHeaders.Add("WWW-Authenticate", new[] { wwwauthenticatechallenge });

        }

        private Task ReturnCompletedTask()
        {
            return Task.FromResult(0);
        }
    }
}
