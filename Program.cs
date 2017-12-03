using System;
using System.Security.Cryptography;
using System.Text;
using CounterKeygen.Helpers;

namespace CounterKeygen
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hi there! Welcome to the Bitcoin private & public key generator");
            Console.WriteLine("Please key in a jibberish string!");

            string jibberish = Console.ReadLine();

            if (jibberish != null) {
                // Step 1: String => Byte[] => SHA256 Byte[]
                // Compute the jibberish
                byte[] sha256jibberish = BitcoinKeyHelper.Sha256(Encoding.Default.GetBytes(jibberish));

                // Debugging
                //Console.WriteLine(BitConverter.ToString(sha256jibberish).Replace("-", "").ToLower());

                // Step 2: Prepend Version number, Append Compression flag, 
                // Append checksum. Checksum is the first 4 bytes of double 
                // sha256 hash of what is being checkedsum-ed.

                // Generate the byte array enough to carry everything
                byte[] modifiedSha256 = new byte[sha256jibberish.Length + 6];

                // Prepend the version
                sha256jibberish.CopyTo(modifiedSha256, 1);
                modifiedSha256[0] = 0x80; // This is the version number, modify this in the future for dynamic parameter

                // Debugging
                //Console.WriteLine(BitConverter.ToString(modifiedSha256).Replace("-", "").ToLower());

                // Append Compression Flag
                modifiedSha256[modifiedSha256.Length - 5] = 0x01;

                // Debugging
                //Console.WriteLine(BitConverter.ToString(modifiedSha256).Replace("-", "").ToLower());

                // Append Checksum

                // Generate the Double SHA256 first
                byte[] doubleSha256 = BitcoinKeyHelper.Sha256(sha256jibberish);

                // Debugging
                //Console.WriteLine(BitConverter.ToString(doubleSha256).Replace("-", "").ToLower());

                // Copy the array over
                // https://stackoverflow.com/questions/733243/how-to-copy-part-of-an-array-to-another-array-in-c
                Array.Copy(doubleSha256, 0, modifiedSha256, modifiedSha256.Length - 4, 4);

                // Debugging
                Console.WriteLine("Your Private Key is:" + BitConverter.ToString(modifiedSha256).Replace("-", "").ToLower());

                // Step 3: Base58 Encode the completed Hash

                // Base58 Encode the private key (This is a reversible encoding process)
                // aka Wallet Import Format
                string encodedPrivateKey = BitcoinKeyHelper.Base58Encode(modifiedSha256);

                Console.WriteLine("Your Base58 Encoded Private Key is: " + encodedPrivateKey);

                // Step 4: Generate the public key via ECD
                byte[] pubKey = BitcoinKeyHelper.GeneratePublicKey(modifiedSha256);

                Console.WriteLine("Your Public Key is: " + BitConverter.ToString(pubKey).Replace("-", "").ToLower());
            }
        }
    }
}
