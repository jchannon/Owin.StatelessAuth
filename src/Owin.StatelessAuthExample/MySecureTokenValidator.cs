namespace Owin.StatelessAuthExample
{
    using RequiresStatelessAuth;

    class MySecureTokenValidator : ITokenValidator
    {
        public bool ValidateUser(string token)
        {
            return true;
        }
    }
}
