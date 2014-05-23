namespace Owin.StatelessAuth
{
    public static class StatelessAuthExtensions
    {
        public static IAppBuilder RequiresStatelessAuth(this IAppBuilder app, ITokenValidator tokenValidator, StatelessAuthOptions options = null)
        {
            return app.Use(typeof (StatelessAuth), tokenValidator, options);
        }
    }
}
