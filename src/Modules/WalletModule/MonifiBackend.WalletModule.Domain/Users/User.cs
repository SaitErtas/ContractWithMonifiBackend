using MonifiBackend.Core.Domain.Base;
using MonifiBackend.WalletModule.Domain.AccountMovements;

namespace MonifiBackend.WalletModule.Domain.Users;

public sealed class User : ReadOnlyBaseDomain<int>
{
    public string Username { get; private set; }
    public string FullName { get; private set; }
    public string Email { get; private set; }

    public string Password { get; private set; }
    public string ConfirmationCode { get; private set; }
    public string ResetPasswordCode { get; private set; }
    public string ReferanceCode { get; private set; }
    public int ReferanceUser { get; private set; }
    public bool Terms { get; private set; }
    public string Fa2Code { get; private set; }

    public Wallet Wallet { get; private set; }

    public static User Default() => new();

    public static User Map(
        int id,
        BaseStatus status,
        string email,
        string password,
        string userName,
        bool terms,
        string resetPassword,
        int referanceUser,
        string referanceCode,
        string confirmationCode,
        string fullName,
        string fa2Code,
        Wallet wallet,
        DateTime createdAt,
        DateTime modifiedAt)
    {
        return new User()
        {
            Id = id,
            Status = status,
            Email = email,
            Password = password,
            Terms = terms,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            ResetPasswordCode = resetPassword,
            ReferanceUser = referanceUser,
            ReferanceCode = referanceCode,
            ConfirmationCode = confirmationCode,
            Username = userName,
            Wallet = wallet,
            FullName = fullName,
            Fa2Code = fa2Code
        };
    }
    public static User Map(
        int id,
        BaseStatus status,
        string email,
        string password,
        string userName,
        bool terms,
        string resetPassword,
        int referanceUser,
        string referanceCode,
        string confirmationCode,
        string fullName,
        string fa2Code,
        DateTime createdAt,
        DateTime modifiedAt)
    {
        return new User()
        {
            Id = id,
            Status = status,
            Email = email,
            Password = password,
            Terms = terms,
            CreatedAt = createdAt,
            ModifiedAt = modifiedAt,
            ResetPasswordCode = resetPassword,
            ReferanceUser = referanceUser,
            ReferanceCode = referanceCode,
            ConfirmationCode = confirmationCode,
            Username = userName,
            FullName = fullName,
            Fa2Code = fa2Code
        };
    }
}