namespace Owin.RequiresStatelessAuth
{
    using System.Security.Claims; 
    
    public interface ITokenValidator
    {
        ClaimsPrincipal ValidateUser(string token);
    }
}
