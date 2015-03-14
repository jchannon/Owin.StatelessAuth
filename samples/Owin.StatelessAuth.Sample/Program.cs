namespace Owin.StatelessAuth.Sample
{
    using System;
    using Microsoft.Owin.Hosting;

    class Program
    {
        static void Main(string[] args)
        {
            using (WebApp.Start<Startup>("http://localhost:12459/"))
            {
                Console.WriteLine("Running on http://localhost:12459/");
                Console.WriteLine("Press enter to exit");
                Console.ReadLine();
            }
        }
    }
}
