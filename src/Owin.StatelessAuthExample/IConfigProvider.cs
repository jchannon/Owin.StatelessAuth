namespace Owin.StatelessAuthExample
{
    public interface IConfigProvider
    {
        string GetAppSetting(string propertyName);
        T GetAppSetting<T>(string propertyName) where T : struct;
    }
}