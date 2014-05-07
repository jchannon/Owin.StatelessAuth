namespace Owin.RequiresStatelessAuth
{
    public static class StatelessAuthExtensions
    {
        public static IAppBuilder RequiresStatelessAuth(this IAppBuilder app, ITokenValidator tokenValidator, StatelessAuthOptions options = null)
        {
            return app.Use<StatelessAuth>(tokenValidator, options);
        }
    }
}
