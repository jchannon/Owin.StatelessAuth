namespace Owin.StatelessAuthExample
{
    using JWT;

    public interface IJwtWrapper
    {
        string Encode(object payload, string key, JwtHashAlgorithm algorithm);
    }
}