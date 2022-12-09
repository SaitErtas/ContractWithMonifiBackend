using MediatR;
using Microsoft.Extensions.Localization;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;
using MonifiBackend.Core.Domain.Utility;
using MonifiBackend.Core.Infrastructure.Localize;
using MonifiBackend.UserModule.Application.Users.Events.LoginUserEmail;
using MonifiBackend.UserModule.Domain.Users;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;

namespace MonifiBackend.UserModule.Application.Users.Commands.Fa2Auth;

internal class Fa2AuthCommandHandler : ICommandHandler<Fa2AuthCommand, Fa2AuthCommandResponse>
{
    private readonly IStringLocalizer<Resource> _stringLocalizer;
    private readonly IUserQueryDataPort _userQueryDataPort;
    private readonly IUserCommandDataPort _userCommandDataPort;
    private readonly IJwtUtils _jwtUtils;
    private readonly IMediator _mediator;
    public Fa2AuthCommandHandler(IUserCommandDataPort userCommandDataPort, IUserQueryDataPort userQueryDataPort, IJwtUtils jwtUtils, IStringLocalizer<Resource> stringLocalizer, IMediator mediator)
    {
        _userQueryDataPort = userQueryDataPort;
        _userCommandDataPort = userCommandDataPort;
        _jwtUtils = jwtUtils;
        _stringLocalizer = stringLocalizer;
        _mediator = mediator;
    }

    public async Task<Fa2AuthCommandResponse> Handle(Fa2AuthCommand request, CancellationToken cancellationToken)
    {

        if(!string.IsNullOrEmpty(request.MetamaskWalletAddress))
        {

            var eamil = await _userQueryDataPort.CheckWalletAddressAsync(request.MetamaskWalletAddress);
            request.Email = eamil.Email;
        }
        


        var user = await _userQueryDataPort.GetEmailAsync(request.Email);
        AppRule.Exists(user, new BusinessValidationException(string.Format(_stringLocalizer["NotFound"], request.Email), $"{string.Format(_stringLocalizer["NotFound"], request.Email)} Email: {request.Email}"));
        AppRule.False(user.Status == Core.Domain.Base.BaseStatus.Blocke, new BusinessValidationException(string.Format(_stringLocalizer["UserBloke"], request.Email), $"{string.Format(_stringLocalizer["UserBloke"], request.Email)} Email: {request.Email}"));
        AppRule.ExistsAndActive(user, new BusinessValidationException(string.Format(_stringLocalizer["NotActivetedUser"], request.Email), $"{string.Format(_stringLocalizer["NotActivetedUser"], request.Email)} Email: {request.Email}"));

        user.AddUserIP(request.IpAddress, "Fa2Auth");

        Thread.CurrentThread.CurrentUICulture = new CultureInfo($"{user.Language.ShortName}");
        user.AddNotification($"{string.Format(_stringLocalizer["LoginNotification"], DateTime.Now.ToString("d"), request.IpAddress)}", user.FullName, default(decimal));

        user.SetFa2Code(string.Empty);

        await _userCommandDataPort.SaveAsync(user);
        // authentication successful so generate jwt token
        JwtSecurityToken jwtSecurityToken = await _jwtUtils.GenerateJwtToken(user);
        var jwtToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

        var loginUserEmailEvent = new LoginUserEmailEvent(user.Id, request.IpAddress);
        await _mediator.Publish(loginUserEmailEvent);

        return new Fa2AuthCommandResponse(user, jwtToken);
    }
    private async Task<string> GenerateReferanceCode()
    {
        string referanceCode;
    TekrarOlustur:
        referanceCode = RandomKeyGenerator.RandomKey(6);
        //Böyle bir referans kodu var mı?
        var isReferanceCode = await _userQueryDataPort.CheckUserReferanceCodeAsync(referanceCode);
        if (!isReferanceCode)
            return referanceCode;
        else
            goto TekrarOlustur;
    }
    private async Task<string> GenerateConfirmationCode()
    {
        string confirmationCode;
    TekrarOlustur:
        confirmationCode = RandomKeyGenerator.RandomKey(6);
        //Böyle bir referans kodu var mı?
        var isConfirmationCode = await _userQueryDataPort.CheckUserConfirmationCodeAsync(confirmationCode);
        if (!isConfirmationCode)
            return confirmationCode;
        else
            goto TekrarOlustur;
    }


    public static string DecryptString(string cipherText, string keyString)
    {
        var fullCipher = Convert.FromBase64String(cipherText);

        var iv = new byte[16];
        var cipher = new byte[16];

        Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);
        var key = Encoding.UTF8.GetBytes(keyString);

        using (var aesAlg = Aes.Create())
        {
            using (var decryptor = aesAlg.CreateDecryptor(key, iv))
            {
                string result;
                using (var msDecrypt = new MemoryStream(cipher))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            result = srDecrypt.ReadToEnd();
                        }
                    }
                }

                return result;
            }
        }
    }

    public static string EncryptString(string text, string keyString)
    {
        var key = Encoding.UTF8.GetBytes(keyString);

        using (var aesAlg = Aes.Create())
        {
            using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
            {
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(text);
                    }

                    var iv = aesAlg.IV;

                    var decryptedContent = msEncrypt.ToArray();

                    var result = new byte[iv.Length + decryptedContent.Length];

                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                    return Convert.ToBase64String(result);
                }
            }
        }
    }

}