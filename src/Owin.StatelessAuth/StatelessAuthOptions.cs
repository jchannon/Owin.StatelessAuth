namespace Owin.StatelessAuth
{
    using System.Collections.Generic;

    public class StatelessAuthOptions
    {
        public IEnumerable<string> IgnorePaths { get; set; }

        public string WWWAuthenticateChallenge { get; set; }

        public bool PassThroughUnauthorizedRequests { get; set; }

        public bool VerifyAuthenticationQueryString { get; set; }

        public bool DecodePlusSignsAsSpacesQueryString { get; set; }
    }
}