using FluentValidation;
using MediatR;
using MonifiBackend.Core.Application.Abstractions;
using MonifiBackend.WalletModule.ArchTests.Base;
using NetArchTest.Rules;
using NUnit.Framework;

namespace MonifiBackend.WalletModule.ArchTests.Application;

public class ApplicationTests : TestBase
{
    //[Test]
    //public void Command_Should_Be_Immutable()
    //{
    //    var types = Types.InAssembly(ApplicationAssembly)
    //        .That()
    //        .ImplementInterface(typeof(ICommand<>))
    //        .GetTypes();

    //    AssertAreImmutable(types);
    //}

    [Test]
    public void Query_Should_Be_Immutable()
    {
        var types = Types.InAssembly(ApplicationAssembly)
            .That().ImplementInterface(typeof(IQuery<>)).GetTypes();

        AssertAreImmutable(types);
    }

    [Test]
    public void CommandHandler_Should_Have_Name_EndingWith_CommandHandler()
    {
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .ImplementInterface(typeof(ICommandHandler<,>))
            .And()
            .DoNotHaveNameMatching(".*Decorator.*").Should()
            .HaveNameEndingWith("CommandHandler")
            .GetResult();

        AssertArchTestResult(result);
    }

    [Test]
    public void QueryHandler_Should_Have_Name_EndingWith_QueryHandler()
    {
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .ImplementInterface(typeof(IQueryHandler<,>))
            .Should()
            .HaveNameEndingWith("QueryHandler")
            .GetResult();

        AssertArchTestResult(result);
    }

    [Test]
    public void Command_And_Query_Handlers_Should_Not_Be_Public()
    {
        var types = Types.InAssembly(ApplicationAssembly)
            .That()
                .ImplementInterface(typeof(IQueryHandler<,>))
                    .Or()
                .ImplementInterface(typeof(ICommandHandler<,>))
            .Should().NotBePublic().GetResult().FailingTypes;

        AssertFailingTypes(types);
    }

    [Test]
    public void Validator_Should_Have_Name_EndingWith_Validator()
    {
        var result = Types.InAssembly(ApplicationAssembly)
            .That()
            .Inherit(typeof(AbstractValidator<>))
            .Should()
            .HaveNameEndingWith("Validator")
            .GetResult();

        AssertArchTestResult(result);
    }

    [Test]
    public void Validators_Should_Not_Be_Public()
    {
        var types = Types.InAssembly(ApplicationAssembly)
            .That()
            .Inherit(typeof(AbstractValidator<>))
            .Should().NotBePublic().GetResult().FailingTypes;

        AssertFailingTypes(types);
    }

    [Test]
    public void MediatR_RequestHandler_Should_NotBe_Used_Directly()
    {
        var types = Types.InAssembly(ApplicationAssembly)
            .That().DoNotHaveName("ICommandHandler`1")
            .Should().ImplementInterface(typeof(IRequestHandler<>))
            .GetTypes();

        List<Type> failingTypes = new List<Type>();
        foreach (var type in types)
        {
            bool isCommandWithResultHandler = type.GetInterfaces().Any(x =>
                x.IsGenericType &&
                x.GetGenericTypeDefinition() == typeof(ICommandHandler<,>));
            bool isQueryHandler = type.GetInterfaces().Any(x =>
                x.IsGenericType &&
                x.GetGenericTypeDefinition() == typeof(IQueryHandler<,>));
            if (!isCommandWithResultHandler && !isQueryHandler)
            {
                failingTypes.Add(type);
            }
        }

        AssertFailingTypes(failingTypes);
    }

    [Test]
    public void Command_With_Result_Should_Not_Return_Unit()
    {
        Type commandWithResultHandlerType = typeof(ICommandHandler<,>);
        IEnumerable<Type> types = Types.InAssembly(ApplicationAssembly)
            .That().ImplementInterface(commandWithResultHandlerType)
            .GetTypes().ToList();

        var failingTypes = new List<Type>();
        foreach (Type type in types)
        {
            Type interfaceType = type.GetInterface(commandWithResultHandlerType.Name);
            if (interfaceType?.GenericTypeArguments[1] == typeof(Unit))
            {
                failingTypes.Add(type);
            }
        }

        AssertFailingTypes(failingTypes);
    }
}
