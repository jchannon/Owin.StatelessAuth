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
        private readonly RequiresStatelessAuthOptions options;

        public RequiresStatelessAuth(Func<IDictionary<string, object>, Task> nextFunc,ITokenValidator tokenValidator, RequiresStatelessAuthOptions options)
        {
            this.nextFunc = nextFunc;
            this.options = options;
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

            var validated = tokenValidator.ValidateUser(token);

            if (!validated)
            {
                environment["owin.ResponseStatusCode"] = 401;
                return ReturnCompletedTask();
            }

            return nextFunc(environment);
        }

        private Task ReturnCompletedTask()
        {
            return Task.FromResult(0);
        }
    }
}
