namespace MonifiBackend.PackageModule.Domain.ReadModel;

public class PackageDetailReadModel
{
    public PackageDetailReadModel(int id, string name)
    {
        Id = id;
        Name = name;
    }

    public int Id { get; set; }
    public string Name { get; set; }
}
