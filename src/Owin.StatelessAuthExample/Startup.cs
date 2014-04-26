namespace Owin.StatelessAuthExample
{
    using RequiresStatelessAuth;

    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.RequiresStatelessAuth(new MySecureTokenValidator())
               .UseNancy();
            
        }
    }
}
