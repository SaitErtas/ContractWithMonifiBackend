namespace MonifiBackend.UserModule.Domain.Versions;

public interface IVersionQueryDataPort
{
    Task<List<Version>> GetAsync();
}
