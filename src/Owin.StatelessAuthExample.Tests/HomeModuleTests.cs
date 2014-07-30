namespace Owin.StatelessAuthExample.Tests
{
    using System.Data;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    using Microsoft.Owin.Testing;

    using Xunit;

    public class HomeModuleTests
    {
        private const string BaseUrl = "http://localhost/";

        [Fact]
        public async Task Root_Should_Return_401_If_Invalid_Header()
        {
            //Given
            var client = this.CreateHttpClient(addAuthHeader: false);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("dodgyheader");

            //When
            var response = await client.GetAsync(BaseUrl);

            //Then
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task Root_Should_Return_200_If_Valid_Header()
        {
            //Given
            var client = this.CreateHttpClient();

            //When
            var response = await client.GetAsync(BaseUrl);

            //Then
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        /// <summary>
        /// Create HTTP client
        /// </summary>
        /// <param name="addAuthHeader"></param>
        /// <remarks>
        /// Could pass in a TinyIOCContainer to this method setup with with fakes to pass to your app's Startup constructor which in turn is passed to Nancy if there is important logic
        /// in your main application's Bootstrapper that needs testing.
        /// You could use a ConfigurableBootstrapper from Nancy to use a test Startup class if you don't have any logic in your app's Bootstrapper using this approach
        /// https://gist.github.com/jchannon/e1e409a702cfd8d5d68a
        /// </remarks>
        /// <returns></returns>
        public HttpClient CreateHttpClient(bool addAuthHeader = true)
        {
            var client = TestServer.Create(builder =>
                new Startup()
                    .Configuration(builder))
                .HttpClient;

            client.DefaultRequestHeaders.Add("Accept", "application/json");

            if (addAuthHeader)
            {
                this.AddAuthHeader(client);
            }

            return client;
        }

        public void AddAuthHeader(HttpClient client)
        {
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue(
                    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJodHRwOi8vaXNzdWVyLmNvbSIsIkF1ZGllbmNlIjoiaHR0cDovL215Y29vbHdlYnNpdGUuY29tIiwiQ2xhaW1zIjpbeyJJc3N1ZXIiOiJMT0NBTCBBVVRIT1JJVFkiLCJPcmlnaW5hbElzc3VlciI6IkxPQ0FMIEFVVEhPUklUWSIsIlByb3BlcnRpZXMiOnt9LCJTdWJqZWN0IjpudWxsLCJUeXBlIjoiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIiwiVmFsdWUiOiJBZG1pbmlzdHJhdG9yIiwiVmFsdWVUeXBlIjoiaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIn0seyJJc3N1ZXIiOiJMT0NBTCBBVVRIT1JJVFkiLCJPcmlnaW5hbElzc3VlciI6IkxPQ0FMIEFVVEhPUklUWSIsIlByb3BlcnRpZXMiOnt9LCJTdWJqZWN0IjpudWxsLCJUeXBlIjoiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvbmFtZSIsIlZhbHVlIjoiRnJlZCIsIlZhbHVlVHlwZSI6Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyJ9XSwiRXhwaXJ5IjoiXC9EYXRlKDQ1NjI0MjIxNDY2MjYpXC8ifQ.SDCE1lfXmvbrkQ5rBQ_UizhdEqUDFR4HHKjiLMkmIpc");
        }
    }
}
