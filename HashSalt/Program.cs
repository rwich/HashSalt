using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HashSalt
{
    class Program
    {
        private const int SaltByteLength = 24;
        private const int DerivedKeyLength = 24;
        private const int IterationCount = 24000;

        public static void Main(string[] args)
        {
            Console.Write("Enter a password: ");
            string password = Console.ReadLine();
            string hash = CreatePasswordHash(password);
            Console.WriteLine("Hash value: " + hash);
            Console.ReadKey();
        }

        private static string CreatePasswordHash(string password)
        {
            byte[] salt = GenerateRandomSalt();
            Console.WriteLine("Salt: " + Convert.ToBase64String(salt));
            Console.WriteLine("Iterations: " + IterationCount);
            byte[] hashValue = GenerateHashValue(password, salt, IterationCount);
            return Convert.ToBase64String(hashValue);
        }

        private static byte[] GenerateRandomSalt()
        {
            var csprng = new RNGCryptoServiceProvider(); // csprng = C# pseudo-random number generator
            var salt = new byte[SaltByteLength]; // 24 bytes = 192 bits
            csprng.GetBytes(salt);
            return salt;
        }

        private static byte[] GenerateHashValue(string password, byte[] salt, int iterationCount)
        {
            byte[] hashValue;
            var valueToHash = string.IsNullOrEmpty(password) ? string.Empty : password;
            using (var pbkdf2 = new Rfc2898DeriveBytes(valueToHash, salt, iterationCount))
            {
                hashValue = pbkdf2.GetBytes(DerivedKeyLength); // 24
            }
            return hashValue;
        }
    }
}
