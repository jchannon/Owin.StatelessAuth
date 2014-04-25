namespace Owin.StatelessAuthExample
{
    using Nancy;

    public class HomeModule : NancyModule
    {
        public HomeModule()
        {
            Get["/"] = _ => "Hello World!";
        }
    }
}
