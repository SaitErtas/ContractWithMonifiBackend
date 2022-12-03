namespace MonifiBackend.Core.Domain.Utility;

public static class TimeExtension
{
    public static DateTime UnixTimeStampToDateTime(this double unixTimeStamp)
    {
        // Unix timestamp is seconds past epoch
        System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
        dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
        return dtDateTime;
    }
    public static DateTime UnixTimeStampToDateTime(this int unixTimeStamp)
    {
        // Unix timestamp is seconds past epoch
        System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
        dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
        return dtDateTime;
    }
    public static DateTime UnixTimeStampToDateTime(this long unixTimeStamp)
    {
        if (unixTimeStamp.ToString().Length == 13)
            unixTimeStamp /= 1000;
        // Unix timestamp is seconds past epoch
        System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
        dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
        return dtDateTime;
    }
    public static DateTime UnixTimeStampToDateTime(this string unixTimeStamp)
    {
        // Unix timestamp is seconds past epoch
        System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
        dtDateTime = dtDateTime.AddSeconds(Convert.ToInt64(unixTimeStamp)).ToLocalTime();
        return dtDateTime;
    }
}
