using MonifiBackend.PackageModule.Domain.Packages;

namespace MonifiBackend.PackageModule.Application.Packages.Queries.GetPackages;

public class GetPackagesQueryResponse
{
    public GetPackagesQueryResponse(List<Package> packages)
    {
        Packages = packages.Select(x => new GetPackageQueryResponse(x)).ToList();
    }

    public List<GetPackageQueryResponse> Packages { get; private set; }
}
public class GetPackageQueryResponse
{
    public GetPackageQueryResponse(Package package)
    {
        Id = package.Id;
        Name = package.Name;
        MinValue = package.MinValue;
        MaxValue = package.MaxValue;
        Title = package.Name;
        Subtitle = package.Name;
        CurrentPlan = false;
        ImgHeight = 100;
        ImgSrc = "/images/pages/pricing-illustration-3.png";
        Icon = package.Icon;
        PlanBenefits = new List<string> { };
        PopularPlan = Name == "Hype" || Name == "Moon";
        YearlyPlan = new List<int> { 1, 2, 3 };
        MonthlyPrice = 100;
        Details = package.Details.Select(s => new GetPackageDetailQueryResponse(s.Id, s.Name, s.Duration, s.Commission)).ToList();
    }
    public int Id { get; private set; }
    public string Name { get; private set; }
    public int MinValue { get; private set; }
    public int MaxValue { get; private set; }
    public string Title { get; private set; }
    public string Subtitle { get; private set; }
    public bool CurrentPlan { get; private set; }
    public bool PopularPlan { get; private set; }
    public int ImgHeight { get; private set; }
    public string ImgSrc { get; private set; }
    public string Icon { get; private set; }

    public List<string> PlanBenefits { get; private set; }
    public List<int> YearlyPlan { get; private set; }
    public int MonthlyPrice { get; private set; }
    public List<GetPackageDetailQueryResponse> Details { get; private set; }
    public string ActionCommand { get; private set; } = "select";
}
public class GetPackageDetailQueryResponse
{
    public GetPackageDetailQueryResponse(int id, string name, int duration, int commission)
    {
        Id = id;
        Name = name;
        Duration = duration;
        Commission = commission;
    }
    public int Id { get; private set; }
    public string Name { get; private set; }
    public int Duration { get; private set; }
    public int Commission { get; private set; }
}
