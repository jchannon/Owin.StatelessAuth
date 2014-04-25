namespace Owin.RequiresStatelessAuth
{
    public static class RequiresStatelessAuthExtensions
    {
        public static IAppBuilder RequiresStatelessAuth(this IAppBuilder app, ITokenValidator tokenValidator)
        {
            return app.Use<RequiresStatelessAuth>(tokenValidator);
        }
    }
}
