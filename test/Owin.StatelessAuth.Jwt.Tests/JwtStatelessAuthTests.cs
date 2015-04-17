namespace Owin.StatelessAuth.Jwt.Tests
{
    using System;
    using System.IdentityModel.Tokens;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    using Microsoft.Owin.Testing;

    using Xunit;

    public class JwtStatelessAuthTests
    {
        [Fact]
        public async Task Root_Should_Return_401_If_Missing_Header()
        {
            //Given
            var server = CreateServer();

            var request = new HttpRequestMessage(HttpMethod.Get, server.BaseAddress);

            //When
            var response = await server.HttpClient.SendAsync(request);

            //Then
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task Root_Should_Return_401_If_Invalid_Header()
        {
            //Given
            var server = CreateServer();

            var request = new HttpRequestMessage(HttpMethod.Get, server.BaseAddress);
            request.Headers.Authorization = new AuthenticationHeaderValue("dodgyheader");

            //When
            var response = await server.HttpClient.SendAsync(request);

            //Then
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task Root_Should_Return_200_If_Valid_Header()
        {
            //Given
            var server = CreateServer();

            var request = new HttpRequestMessage(HttpMethod.Get, server.BaseAddress);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiQWRtaW5pc3R" + 
                "yYXRvciIsInVuaXF1ZV9uYW1lIjoiZnJlZCIsImlzcyI6Imh0dHA6Ly9pc3N" +
                "1ZXIuY29tIiwiYXVkIjoiaHR0cDovL215Y29vbHdlYnNpdGUuY29tIiwiZXh" +
                "wIjoxNzQ0OTMxNDk4fQ.mhBdVPodkq4roJYfNfv6IyyW7_DGbjRuwHp2mBXyx7A");

            //When
            var response = await server.HttpClient.SendAsync(request);

            //Then
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        
        public TestServer CreateServer()
        {
            return TestServer.Create(app =>
            {
                var key = new InMemorySymmetricSecurityKey(Convert.FromBase64String(
                    "Srtjyi8wMFfmP9Ub8U2ieVGAcrP/7gK3VM/K6KfJ/fI="));
                
                app.RequiresJwtAuth("http://issuer.com", "http://mycoolwebsite.com", key);

                app.Run(context => Task.FromResult<object>(null));
            });
        }
    }
}
