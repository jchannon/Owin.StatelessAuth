#Owin.StatelessAuth

An OWIN middleware component to determine authorized requests using tokens in the Authorization header.

If the request is authenticated then the middleware will call the next item in the queue otherwise a HTTP Status Code of 401 is returned and the request is ended.

##Usage

	public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
             app
               .RequiresStatelessAuth(
               	  new MySecureTokenValidator()
               	  new StatelessAuthOptions() {IgnorePaths = new List<string>(new []{"/login","/content"})})
               .UseNancy();
        }
    }

For a more in depth look at usage please see this blog post - http://blog.jonathanchannon.com/2014/05/07/introducing-owin-statelessauth-with-nancy-angular-demo/
