namespace Owin.StatelessAuthExample
{
    using System.Linq;
    using System.Security.Claims;
    using Nancy;
    using Nancy.Bootstrapper;
    using Nancy.Owin;
    using Nancy.TinyIoc;

    public  class Bootstrapper : DefaultNancyBootstrapper
    {
        protected override void RequestStartup(TinyIoCContainer container, IPipelines pipelines, NancyContext context)
        {
            base.RequestStartup(container, pipelines, context);
            var owinEnvironment = context.GetOwinEnvironment();
            var user = owinEnvironment["server.User"] as ClaimsPrincipal;
            context.CurrentUser = new DemoUserIdentity()
            {
                UserName = user.Identity.Name,
                Claims = user.Claims.Select(x => x.Value)
            };
        }
    }
}
