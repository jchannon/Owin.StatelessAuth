namespace Owin.RequiresStatelessAuth
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class RequiresStatelessAuth
    {
        private readonly ITokenValidator tokenValidator;
        private readonly RequireStatelessAuthOptions requireStatelessAuthOptions;
        private readonly Func<IDictionary<string, object>, Task> nextFunc;
        private const string ServerUser = "server.User";

        public RequiresStatelessAuth(Func<IDictionary<string, object>, Task> nextFunc, ITokenValidator tokenValidator, RequireStatelessAuthOptions requireStatelessAuthOptions)
        {
            this.nextFunc = nextFunc;
            this.tokenValidator = tokenValidator;
            this.requireStatelessAuthOptions = requireStatelessAuthOptions;
        }

        public Task Invoke(IDictionary<string, object> environment)
        {
            if (!environment.ContainsKey("owin.RequestPath"))
            {
                throw new ApplicationException("Invalid OWIN request. Expected owin.RequestPath, but not present.");
            }

            var path = (string) environment["owin.RequestPath"];

            if (requireStatelessAuthOptions != null && requireStatelessAuthOptions.IgnorePaths.Contains(path, StringComparer.OrdinalIgnoreCase))
            {
                return nextFunc(environment);
            }

            var requestHeaders = (IDictionary<string, string[]>)environment["owin.RequestHeaders"];
            if (!requestHeaders.ContainsKey("Authorization"))
            {
                environment["owin.ResponseStatusCode"] = 401;
                return ReturnCompletedTask();
            }

            var token = requestHeaders["Authorization"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(token))
            {
                environment["owin.ResponseStatusCode"] = 401;
                return ReturnCompletedTask();
            }

            var validatedUser = tokenValidator.ValidateUser(token);

            if (validatedUser == null)
            {
                environment["owin.ResponseStatusCode"] = 401;
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

        private Task ReturnCompletedTask()
        {
            return Task.FromResult(0);
        }
    }
}
