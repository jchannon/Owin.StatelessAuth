namespace Owin.RequiresStatelessAuth
{
    public static class RequiresStatelessAuthExtensions
    {
        public static IAppBuilder RequiresStatelessAuth(this IAppBuilder app, RequiresStatelessAuthOptions options)
        {
            return app.Use<RequiresStatelessAuth>(options);
        }
    }
}
