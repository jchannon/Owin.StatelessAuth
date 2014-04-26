namespace Owin.StatelessAuthExample
{
    using RequiresStatelessAuth;
    using System.Security.Claims;

    class MySecureTokenValidator : ITokenValidator
    {
        public ClaimsPrincipal ValidateUser(string token)
        {
            return new ClaimsPrincipal();
        }
    }
}
