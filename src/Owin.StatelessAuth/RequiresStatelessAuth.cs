namespace Owin.RequiresStatelessAuth
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class RequiresStatelessAuth
    {
        private readonly ITokenValidator tokenValidator;
        private readonly Func<IDictionary<string, object>, Task> nextFunc;
        private const string ServerUser = "server.User";

        public RequiresStatelessAuth(Func<IDictionary<string, object>, Task> nextFunc, ITokenValidator tokenValidator)
        {
            this.nextFunc = nextFunc;
            this.tokenValidator = tokenValidator;
        }

        public Task Invoke(IDictionary<string, object> environment)
        {
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
