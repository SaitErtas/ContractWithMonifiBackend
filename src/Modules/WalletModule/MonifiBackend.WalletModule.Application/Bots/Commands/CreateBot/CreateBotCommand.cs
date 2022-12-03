using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;

namespace MonifiBackend.WalletModule.Application.Bots.Commands.CreateBot;

public class CreateBotCommand : ICommand<CreateBotCommandResponse>
{
    public int Hour { get; set; }
    public int Minute { get; set; }
    public int WorkingRange { get; set; }
    public int Range { get; set; }
    public int Amount { get; set; }
    public int PackageDetailId { get; set; }
}
internal class CreateBotCommandValidator : AbstractValidator<CreateBotCommand>
{
    public CreateBotCommandValidator()
    {
    }
}