namespace MonifiBackend.Core.Domain.Utility;

public static class MathExtensions
{
    public static decimal PercentageCalculation(decimal amount, decimal commission)
    {
        if (commission == 0)
            return amount;
        var total = (amount * commission) / 100;
        total = total + amount;
        return total;
    }
}
