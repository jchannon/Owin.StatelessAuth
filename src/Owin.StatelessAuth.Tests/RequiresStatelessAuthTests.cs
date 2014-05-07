namespace Owin.RequiresHttps.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using FakeItEasy;
    using RequiresStatelessAuth;
    using Xunit;

    public class RequiresStatelessAuthTests
    {
        [Fact]
        public void Should_Execute_Next_If_Validated()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc());
            var environment = new Dictionary<string, object>
            {
                {"owin.RequestHeaders", new Dictionary<string, string[]>() {{"Authorization", new[] {"mysecuretoken"}}}},
                {"owin.RequestPath", "/"}
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
           Assert.Throws<ApplicationException>(()=>owinhttps.Invoke(environment));
        }

        [Fact]
        public void Should_Execute_Next_If_Path_Ignored()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc(), requireStatelessAuthOptions:new RequireStatelessAuthOptions(){IgnorePaths = new List<string>(){"/"}});
            var environment = new Dictionary<string, object>
            {
                {"owin.RequestHeaders", new Dictionary<string, string[]>() {{"Authorization", new[] {"mysecuretoken"}}}},
                {"owin.RequestPath", "/"}
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(123, ((Task<int>)task).Result);
            
        }

        [Fact]
        public void Should_Return_401_If_No_Auth_Header_And_Completed_Task()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc());
            var environment = new Dictionary<string, object>
            {
                {"owin.RequestHeaders", new Dictionary<string, string[]>() },
                {"owin.RequestPath", "/"}
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.Equal(401, environment["owin.ResponseStatusCode"]);
            Assert.Equal(true, task.IsCompleted);
            Assert.Equal(0, ((Task<int>)task).Result);
        }

        [Fact]
        public void Should_Return_401_If_Null_Token_And_Completed_Task()
        {
            //Given
            var owinhttps = GetStatelessAuth(GetNextFunc());
            var environment = new Dictionary<string, object>
            {
                {"owin.RequestHeaders", new Dictionary<string, string[]>() {{"Authorization", new[] {""}}}},
                {"owin.RequestPath", "/"}
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
            var owinhttps = GetStatelessAuth(GetNextFunc(), tokenValidator:fakeTokenValidator);
            var environment = new Dictionary<string, object>
            {
                {"owin.RequestHeaders", new Dictionary<string, string[]>() {{"Authorization", new[] {"123"}}}},
                {"owin.RequestPath", "/"}
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
                {"owin.RequestHeaders", new Dictionary<string, string[]>() {{"Authorization", new[] {"mysecuretoken"}}}},
                {"owin.RequestPath", "/"}
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            Assert.True(environment.ContainsKey("server.User"));
        }

        [Fact]
        public void Should_Override_User_In_Owin_Environment()
        {
            //Given
            var fakeTokenValidator = A.Fake<ITokenValidator>();
            A.CallTo(() => fakeTokenValidator.ValidateUser(A<string>.Ignored))
                .Returns(
                     new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim(ClaimTypes.Role, "DumbUser") }, "Token"))
                );

            var owinhttps = GetStatelessAuth(GetNextFunc(), tokenValidator:fakeTokenValidator);
            var environment = new Dictionary<string, object>
            {
                {"owin.RequestHeaders", new Dictionary<string, string[]>() {{"Authorization", new[] {"mysecuretoken"}}}},
                {"owin.RequestPath", "/"},
                {"server.User", new ClaimsPrincipal(new ClaimsIdentity(new Claim[] {new Claim(ClaimTypes.Role, "Administrator")}, "Token"))}
            };

            //When
            var task = owinhttps.Invoke(environment);

            //Then
            var user = environment["server.User"] as ClaimsPrincipal;

            Assert.True(user.HasClaim(ClaimTypes.Role,"DumbUser"));
        }

        public Func<IDictionary<string, object>, Task> GetNextFunc()
        {
            return objects => Task.FromResult(123);
        }

        public RequiresStatelessAuth GetStatelessAuth(Func<IDictionary<string, object>, Task> nextFunc, ITokenValidator tokenValidator = null, RequireStatelessAuthOptions requireStatelessAuthOptions=null)
        {
            tokenValidator = tokenValidator ?? GetFakeTokenValidator();
            requireStatelessAuthOptions = requireStatelessAuthOptions ?? GetStatelessAuthOptions();
            return new RequiresStatelessAuth(nextFunc, tokenValidator,requireStatelessAuthOptions);
        }

        private RequireStatelessAuthOptions GetStatelessAuthOptions()
        {
            return new RequireStatelessAuthOptions(){IgnorePaths = Enumerable.Empty<string>()};
        }

        private ITokenValidator GetFakeTokenValidator()
        {
            var fakeTokenValidator = A.Fake<ITokenValidator>();
            A.CallTo(() => fakeTokenValidator.ValidateUser(A<string>.Ignored))
                .Returns(
                     new ClaimsPrincipal(new ClaimsIdentity(new Claim[] {new Claim(ClaimTypes.Role, "Administrator")}, "Token"))
                );
            return fakeTokenValidator;
        }
    }
}
