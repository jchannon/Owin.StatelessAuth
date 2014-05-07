namespace Owin.StatelessAuth
{
    using System.Security.Claims;

    public interface ITokenValidator
    {
        ClaimsPrincipal ValidateUser(string token);
    }
}
