using MonifiBackend.Core.Domain.Abstractions;
using MonifiBackend.Core.Domain.Exceptions;

namespace MonifiBackend.Core.Domain.Utility
{
    public static class AppRule
    {
        public static void NotNullOrEmpty<TException>(string value, TException exception) where TException : BaseException
        {
            if (string.IsNullOrEmpty(value)) throw exception;
        }
        public static void NotNullOrEmpty<TException>(string value, params object[] exceptionConsturctorArgs)
            where TException : BaseException
        {
            if (string.IsNullOrEmpty(value))
                throw (TException)Activator.CreateInstance(typeof(TException), exceptionConsturctorArgs);
        }
        public static void NotNegative<TException>(int value, TException exception) where TException : BaseException
        {
            if (value.IsNegative()) throw exception;
        }
        public static void NotNegative<TException>(int value, params object[] exceptionConsturctorArgs)
            where TException : BaseException
        {
            if (value.IsNegative())
                throw (TException)Activator.CreateInstance(typeof(TException), exceptionConsturctorArgs);
        }
        public static void NotNegativeOrZero<TException>(int value, TException exception) where TException : BaseException
        {
            if (value.IsNegativeOrZero()) throw exception;
        }
        public static void NotNegativeOrZero<TException>(decimal value, TException exception) where TException : BaseException
        {
            if (value.IsNegativeOrZero()) throw exception;
        }
        public static void NotNegativeOrZero<TException>(int value, params object[] exceptionConsturctorArgs)
            where TException : BaseException
        {
            if (value.IsNegativeOrZero())
                throw (TException)Activator.CreateInstance(typeof(TException), exceptionConsturctorArgs);
        }
        public static void True<TException>(bool value, TException exception) where TException : BaseException
        {
            if (!value) throw exception;
        }
        public static void True<TException>(bool value, params object[] exceptionConsturctorArgs)
            where TException : BaseException
        {
            if (!value)
                throw (TException)Activator.CreateInstance(typeof(TException), exceptionConsturctorArgs);
        }
        public static void False<TException>(bool value, TException exception) where TException : BaseException
        {
            if (value) throw exception;
        }
        public static void False<TException>(bool value, params object[] exceptionConsturctorArgs)
            where TException : BaseException
        {
            if (value)
                throw (TException)Activator.CreateInstance(typeof(TException), exceptionConsturctorArgs);
        }
        public static void ExistsAndActive<TDomain, TException>(TDomain value, TException exception) where TException : BaseException where TDomain : IReadOnlyDomain
        {
            if (value == null || !value.IsExist() || !value.IsActive()) throw exception;
        }
        public static void Exists<TDomain, TException>(TDomain value, TException exception) where TException : BaseException where TDomain : IReadOnlyDomain
        {
            if (value == null || !value.IsExist()) throw exception;
        }
        public static void ExistsAndPassive<TDomain, TException>(TDomain value, TException exception) where TException : BaseException where TDomain : IReadOnlyDomain
        {
            if (value == null || !value.IsExist() || !value.IsPassive()) throw exception;
        }
    }
}
