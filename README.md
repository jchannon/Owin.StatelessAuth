#Owin.RequiresHttps

An OWIN middleware component to determine HTTPS requests.

If the request is `https` then the middleware will call the next item in the queue otherwise a HTTP Status Code of 401 is returned and the request is ended.

There is an optional RequiresHttpsOptions tool which will route any `http` traffic to a `https` location if specified

##Usage

	public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var redirectOptions = new RequiresHttpsOptions() { RedirectToHttpsPath = "https://mysecureapp.com" };
            app
                .RequiresHttps(redirectOptions)
                .UseNancy();
        }
    }

