namespace Owin.RequiresStatelessAuth
{
    using System.Collections.Generic;

    public class RequireStatelessAuthOptions
    {
        public IEnumerable<string> IgnorePaths { get; set; }
    }
}
