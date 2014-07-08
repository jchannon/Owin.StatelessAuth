namespace Owin.StatelessAuth
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;
    using Minimatch;

    public class StatelessAuth
    {
        private readonly ITokenValidator tokenValidator;
        private readonly StatelessAuthOptions statelessAuthOptions;
        private readonly Func<IDictionary<string, object>, Task> nextFunc;
        private const string ServerUser = "server.User";

        public StatelessAuth(Func<IDictionary<string, object>, Task> nextFunc, ITokenValidator tokenValidator, StatelessAuthOptions statelessAuthOptions)
        {
            this.nextFunc = nextFunc;
            this.tokenValidator = tokenValidator;
            this.statelessAuthOptions = statelessAuthOptions;
        }

        public Task Invoke(IDictionary<string, object> environment)
        {
            if (!environment.ContainsKey("owin.RequestPath"))
            {
                throw new ApplicationException("Invalid OWIN request. Expected owin.RequestPath, but not present.");
            }

            var path = Uri.UnescapeDataString((string)environment["owin.RequestPath"]);

            if (statelessAuthOptions != null)
            {
                foreach (var ignorePath in statelessAuthOptions.IgnorePaths)
                {
                    var mm = new Minimatcher(ignorePath);

                    if (mm.IsMatch(path))
                    {
                        return nextFunc(environment);
                    }
                }
            }

            var requestHeaders = (IDictionary<string, string[]>)environment["owin.RequestHeaders"];
            if (!requestHeaders.ContainsKey("Authorization"))
            {
                SetResponseStatusCodeAndHeader(environment);
                return ReturnCompletedTask();
            }

            var token = requestHeaders["Authorization"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(token))
            {
                SetResponseStatusCodeAndHeader(environment);
                return ReturnCompletedTask();
            }

            var validatedUser = tokenValidator.ValidateUser(token);

            if (validatedUser == null)
            {
                SetResponseStatusCodeAndHeader(environment);
                return ReturnCompletedTask();
            }

            if (environment.ContainsKey(ServerUser))
            {
                environment[ServerUser] = validatedUser;
            }
            else
            {
                environment.Add(ServerUser, validatedUser);
            }

            return nextFunc(environment);
        }

        private void SetResponseStatusCodeAndHeader(IDictionary<string, object> environment)
        {
            environment["owin.ResponseStatusCode"] = 401;


            if (statelessAuthOptions != null && !string.IsNullOrWhiteSpace(statelessAuthOptions.WWWAuthenticateChallenge))
            {
                var wwwauthenticatechallenge = statelessAuthOptions.WWWAuthenticateChallenge;

                if (!environment.ContainsKey("owin.ResponseHeaders"))
                {
                    environment.Add("owin.ResponseHeaders", new Dictionary<string, string[]>());
                }

                var responseHeaders = (IDictionary<string, string[]>)environment["owin.ResponseHeaders"];
                responseHeaders.Add("WWW-Authenticate", new[] { wwwauthenticatechallenge });
            }
        }

        private Task ReturnCompletedTask()
        {
            return Task.FromResult(0);
        }

        public bool PathMatchesIgnoredPath(string pattern, string path)
        {
            var regex = FindFilesPatternToRegex.Convert(pattern);
            return regex.IsMatch(path);
        }

        internal static class FindFilesPatternToRegex
        {
            private static readonly Regex HasQuestionMarkRegEx = new Regex(@"\?", RegexOptions.Compiled);
            private static readonly Regex IlegalCharactersRegex = new Regex("[" + @"\/:<>|" + "\"]", RegexOptions.Compiled);
            private static readonly Regex CatchExtentionRegex = new Regex(@"^\s*.+\.([^\.]+)\s*$", RegexOptions.Compiled);
            private const string NonDotCharacters = @"[^.]*";

            public static Regex Convert(string pattern)
            {
                if (pattern == null)
                {
                    throw new ArgumentNullException();
                }
                pattern = pattern.Trim();
                if (pattern.Length == 0)
                {
                    throw new ArgumentException("Pattern is empty.");
                }
                if (IlegalCharactersRegex.IsMatch(pattern))
                {
                    throw new ArgumentException("Patterns contains ilegal characters.");
                }
                bool hasExtension = CatchExtentionRegex.IsMatch(pattern);
                bool matchExact = false;
                if (HasQuestionMarkRegEx.IsMatch(pattern))
                {
                    matchExact = true;
                }
                else if (hasExtension)
                {
                    matchExact = CatchExtentionRegex.Match(pattern).Groups[1].Length != 3;
                }
                string regexString = Regex.Escape(pattern);
                regexString = "^" + Regex.Replace(regexString, @"\\\*", ".*");
                regexString = Regex.Replace(regexString, @"\\\?", ".");
                if (!matchExact && hasExtension)
                {
                    regexString += NonDotCharacters;
                }
                regexString += "$";
                var regex = new Regex(regexString, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                return regex;
            }
        }
    }
}
