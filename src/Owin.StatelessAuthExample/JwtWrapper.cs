namespace Owin.StatelessAuthExample
{
    using JWT;

    public class JwtWrapper : IJwtWrapper
    {
        public string Encode(object payload, string key, JwtHashAlgorithm algorithm)
        {
            return JsonWebToken.Encode(payload, key, algorithm);
        }
    }
}