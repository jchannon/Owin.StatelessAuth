namespace Owin.RequiresStatelessAuth
{
    public interface ITokenValidator
    {
        bool ValidateUser(string token);
    }
}