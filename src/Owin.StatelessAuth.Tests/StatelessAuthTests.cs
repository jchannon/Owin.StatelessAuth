namespace Owin.StatelessAuth.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using FakeItEasy;
    using Xunit;
    using Xunit.Extensions;

    public class StatelessAuthTests
    {
        private const string ServerUser = "server.User";

        [Fact]
        public void Should_Execute_Next_If_Validated()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc());
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() { { "Authorization", new[] { "mysecuretoken" } } } },
                { "owin.RequestPath", "/" }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(123, ((Task<int>)task).Result);
        }

        [Fact]
        public void Should_Throw_Application_Exception_If_No_Path()
        {
            var owinhttps = GetStatelessAuth(GetNextFunc());
            var environment = new Dictionary<string, object>
            {
            };

            //When
            Assert.Throws<ApplicationException>(() => owinhttps.Invoke(environment));
        }

        [Theory]
        [InlineData("/")]
        [InlineData("/vincentvega/royalewithcheese.css")]
        [InlineData("/vincentvega/fred.css")]
        [InlineData("/vincentvega/another.css")]
        public void Should_Execute_Next_If_Path_Ignored(string requestpath)
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc(), statelessAuthOptions: new StatelessAuthOptions() { IgnorePaths = new List<string>() { "/", "/vincentvega/*.css" } });
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() { { "Authorization", new[] { "mysecuretoken" } } } },
                { "owin.RequestPath", requestpath }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(123, ((Task<int>)task).Result);
            Assert.False(environment.ContainsKey(ServerUser));
        }

        [Theory]
        [InlineData("/api/user")]
        [InlineData("/api/user/js/main.css")]
        public void Should_Return_401_If_Request_Path_Doesnt_Meet_Ignore_List_And_Empty_Auth_Header(string requestpath)
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc(), statelessAuthOptions: new StatelessAuthOptions() { IgnorePaths = new List<string>() { "/api/user/js/*.js", "/api/products" } });
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() { { "Authorization", new[] { "" } } } }, //empty header so it falls through ignorelist check
                { "owin.RequestPath", requestpath }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(401, environment["owin.ResponseStatusCode"]);
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(0, ((Task<int>)task).Result);
        }

        [Theory]
        [InlineData("/api/user")]
        [InlineData("/api/user/js/main.css")]
        public void Should_Execute_Next_If_Request_Path_Doesnt_Meet_Ignore_List_And_Empty_Auth_Header_And_PassThrough_Is_Enabled(string requestpath)
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc(), statelessAuthOptions: new StatelessAuthOptions() { IgnorePaths = new List<string>() { "/api/user/js/*.js", "/api/products" }, PassThroughUnauthorizedRequests = true });
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() { { "Authorization", new[] { "" } } } }, //empty header so it falls through ignorelist check
                { "owin.RequestPath", requestpath }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(123, ((Task<int>)task).Result);
            Assert.False(environment.ContainsKey(ServerUser));
        }

        [Fact]
        public void Should_Return_401_If_No_Auth_Header_And_Completed_Task()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc());
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() },
                { "owin.RequestPath", "/" }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(401, environment["owin.ResponseStatusCode"]);
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(0, ((Task<int>)task).Result);
        }

        [Fact]
        public void Should_Execute_Next_If_No_Auth_Header_And_PassThrough_Is_Enabled()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc(), statelessAuthOptions: new StatelessAuthOptions() { PassThroughUnauthorizedRequests = true });
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() },
                { "owin.RequestPath", "/" }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(123, ((Task<int>)task).Result);
            Assert.False(environment.ContainsKey(ServerUser));
        }

        [Fact]
        public void Should_Return_401_If_Null_Token_And_Completed_Task()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc());
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() { { "Authorization", new[] { "" } } } },
                { "owin.RequestPath", "/" }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(401, environment["owin.ResponseStatusCode"]);
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(0, ((Task<int>)task).Result);
        }

        [Fact]
        public void Should_Return_401_If_Invalid_Token_And_Completed_Task()
        {
            //Given
            var fakeTokenValidator = GetFakeTokenValidator();
            A.CallTo(() => fakeTokenValidator.ValidateUser("123")).Returns(null);
            var owinhttps = GetStatelessAuth(GetNextFunc(), tokenValidator: fakeTokenValidator);
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() { { "Authorization", new[] { "123" } } } },
                { "owin.RequestPath", "/" }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(401, environment["owin.ResponseStatusCode"]);
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(0, ((Task<int>)task).Result);
        }

        [Fact]
        public void Should_Add_User_To_Owin_Environment()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc());
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() { { "Authorization", new[] { "mysecuretoken" } } } },
                { "owin.RequestPath", "/" }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.True(environment.ContainsKey(ServerUser));
        }

        [Fact]
        public void Should_Override_User_In_Owin_Environment()
        {

            //Given
            var fakeTokenValidator = A.Fake<ITokenValidator>();

            var secureuser = new ClaimsPrincipal();           
            var claimsIdentity = new ClaimsIdentity("Token");
            claimsIdentity.AddClaim(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "DumbUser"));
            secureuser.AddIdentity(claimsIdentity);

            A.CallTo(() => fakeTokenValidator.ValidateUser(A<string>.Ignored))
                .Returns(secureuser);

            var owinhttps = GetStatelessAuth(GetNextFunc(), tokenValidator: fakeTokenValidator);

            //TODO Tidy on 3.8 Mono release
            var overriddenUser = new ClaimsPrincipal();
            var overriddenIdentity = new ClaimsIdentity("Token");
            overriddenIdentity.AddClaim(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Administrator"));
            overriddenUser.AddIdentity(overriddenIdentity);

            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() { { "Authorization", new[] { "mysecuretoken" } } } },
                { "owin.RequestPath", "/" },
                { ServerUser, overriddenUser }
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            var user = environment[ServerUser] as ClaimsPrincipal;

            //TODO Tidy on 3.8 Mono release
            Assert.True(user.HasClaim(x => x.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" && x.Value == "DumbUser"));
        }

        [Fact]
        public void Should_Return_WWW_Authenticate_Header_In_Options()
        {
            //Given
            var options = new StatelessAuthOptions()
            {
                IgnorePaths = Enumerable.Empty<string>(),
                WWWAuthenticateChallenge = "Basic realm=\"WallyWorld\""
            };

            var owinhttps = GetStatelessAuth(GetNextFunc(), statelessAuthOptions: options);
            
            var environment = new Dictionary<string, object>
            {
                { "owin.RequestHeaders", new Dictionary<string, string[]>() },
                { "owin.RequestPath", "/" }
            };

            //When
            var task = owinhttps.Invoke(environment);

            var responseHeaders = (IDictionary<string, string[]>)environment["owin.ResponseHeaders"];

            //Then
            Assert.Equal("Basic realm=\"WallyWorld\"", responseHeaders["WWW-Authenticate"].First());
        }

        public Func<IDictionary<string, object>, Task> GetNextFunc()
        {
            return objects => Task.FromResult(123);
        }

        public StatelessAuth GetStatelessAuth(Func<IDictionary<string, object>, Task> nextFunc, ITokenValidator tokenValidator = null, StatelessAuthOptions statelessAuthOptions = null)
        {
            tokenValidator = tokenValidator ?? GetFakeTokenValidator();
            statelessAuthOptions = statelessAuthOptions ?? GetStatelessAuthOptions();
            return new StatelessAuth(nextFunc, tokenValidator, statelessAuthOptions);
        }

        private StatelessAuthOptions GetStatelessAuthOptions()
        {
            return new StatelessAuthOptions() { IgnorePaths = Enumerable.Empty<string>(), WWWAuthenticateChallenge = "Digest" };
        }

        private ITokenValidator GetFakeTokenValidator()
        {
            var fakeTokenValidator = A.Fake<ITokenValidator>();
            A.CallTo(() => fakeTokenValidator.ValidateUser(A<string>.Ignored))
                .Returns(
                new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Administrator") }, "Token"))
            );
            return fakeTokenValidator;
        }
    }
}
