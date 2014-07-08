namespace Owin.StatelessAuthExample
{
    using System.Collections.Generic;
    using StatelessAuth;

    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.RequiresStatelessAuth(new MySecureTokenValidator(new ConfigProvider()), new StatelessAuthOptions() {IgnorePaths = new List<string>(new []{"/login","/content/*.js"})})
                .UseNancy();

        }
    }
}
