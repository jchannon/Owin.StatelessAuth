#Owin.StatelessAuth

An OWIN middleware component to determine authorized requests using tokens in the Authorization header.

If the request is authenticated then the middleware will call the next item in the queue otherwise a HTTP Status Code of 401 is returned and the request is ended.

##Usage

	public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app
                .RequiresStatelessAuth()
                .UseNancy();
        }
    }

