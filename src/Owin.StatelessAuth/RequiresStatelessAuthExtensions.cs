namespace Owin.RequiresStatelessAuth
{
    public static class RequiresStatelessAuthExtensions
    {
        public static IAppBuilder RequiresStatelessAuth(this IAppBuilder app, ITokenValidator tokenValidator, RequireStatelessAuthOptions options = null)
        {
            return app.Use<RequiresStatelessAuth>(tokenValidator, options);
        }
    }
}
