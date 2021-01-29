using System;

namespace PE
{

    [Serializable]
    public class PeException : Exception
    {
        public PeException()
        {

        }

        public PeException(string message) : base(message)
        {
            Console.WriteLine(message);
        }

        public PeException(string message, Exception innerException)
            : base(message, innerException)
        {

        }
    }
}
