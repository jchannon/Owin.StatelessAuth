namespace Owin.RequiresStatelessAuth
{
    using System.Collections.Generic;

    public class StatelessAuthOptions
    {
        public IEnumerable<string> IgnorePaths { get; set; }
    }
}
