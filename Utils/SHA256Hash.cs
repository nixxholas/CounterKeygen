using System;
using System.Security.Cryptography;
using System.Text;

namespace CounterKeygen.Utils
{
    public class SHA256Hash
    {
        /// <summary>
        /// Gets the hash of a given string input
        /// </summary>
        /// <returns></returns>
        public static string Hash(string input)
        {
            using (var sha = SHA256.Create())
            {
                var computedHash = sha.ComputeHash(Encoding.Unicode.GetBytes(input));
                return Convert.ToBase64String(computedHash);
            }
        }
    }
}
