using MonifiBackend.UserModule.Application.Users.Commands.RegisterUser;
using MonifiBackend.UserModule.Domain.Users;
using MonifiBackend.UserModule.Infrastructure.Users;
using NetArchTest.Rules;
using NUnit.Framework;
using System.Reflection;

namespace MonifiBackend.UserModule.ArchTests.Base
{
    public abstract class TestBase
    {
        protected static Assembly ApplicationAssembly => typeof(RegisterUserCommand).Assembly;

        protected static Assembly DomainAssembly => typeof(User).Assembly;

        protected static Assembly InfrastructureAssembly => typeof(UserCommandDataAdapter).Assembly;

        protected static void AssertAreImmutable(IEnumerable<Type> types)
        {
            IList<Type> failingTypes = new List<Type>();
            foreach (var type in types)
            {
                if (type.GetFields().Any(x => !x.IsInitOnly) || type.GetProperties().Any(x => x.CanWrite))
                {
                    failingTypes.Add(type);
                    break;
                }
            }

            AssertFailingTypes(failingTypes);
        }

        protected static void AssertFailingTypes(IEnumerable<Type> types)
        {
            Assert.That(types, Is.Null.Or.Empty);
        }

        protected static void AssertArchTestResult(TestResult result)
        {
            AssertFailingTypes(result.FailingTypes);
        }
    }
}
