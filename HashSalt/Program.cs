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
            string hash = CornedBeef(password);
            Console.WriteLine("All hashed together: " + hash);
            Console.ReadKey();
        }

        private static string CornedBeef(string password)
        {
            byte[] salt = GenerateSalt();
            Console.WriteLine("Salt: " + Convert.ToBase64String(salt));
            Console.WriteLine("Iterations: " + IterationCount);
            byte[] hashValue = GenerateHash(password, salt, IterationCount);
            return Convert.ToBase64String(hashValue);
        }

        private static byte[] GenerateSalt()
        {
            var csprng = new RNGCryptoServiceProvider();
            var salt = new byte[SaltByteLength]; // 24
            csprng.GetBytes(salt);
            return salt;
        }

        private static byte[] GenerateHash(string password, byte[] salt, int iterationCount)
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
