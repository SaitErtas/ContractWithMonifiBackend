using FluentValidation;
using MonifiBackend.Core.Application.Abstractions;
using System.Text.Json.Serialization;

namespace MonifiBackend.WalletModule.Application.Bots.Commands.DeleteBot;

public class DeleteBotCommand : ICommand<DeleteBotCommandResponse>
{
    public DeleteBotCommand(int id)
    {
        Id = id;
    }

    [JsonIgnore]
    public int Id { get; set; }
}
internal class DeleteBotCommandValidator : AbstractValidator<DeleteBotCommand>
{
    public DeleteBotCommandValidator()
    {
    }
}