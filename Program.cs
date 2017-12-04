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
            while (true) {
                Console.WriteLine("Hi there! Welcome to the Bitcoin key generator");
                Console.WriteLine("==============================================");
                Console.WriteLine("Please select an option:");
                Console.WriteLine();
                Console.WriteLine("1 - Create Basic Keys");
                Console.WriteLine("2 - Create BIP32 Compliant Keys");
                Console.WriteLine("3 - Create BIP44 Private Keys");
                Console.WriteLine("4 - Generate a child key from an X Key");
                Console.WriteLine();
                Console.WriteLine("0 - Exit");

                while (true) {
                    string choice = Console.ReadLine();
                    int result = 0;

                    if (int.TryParse(choice, out result))
                    {
                        if (result == 0) {
                            Console.WriteLine("Goodbye!");
                            Environment.Exit(0);
                        }

                        switch (result) {
                            case 1:
                                Console.Clear();
                                loadCreateBasicKeys();
                                Console.Clear();

                                goto BREAK;
                            default:
                                Console.WriteLine("Invalid input, please try again.");
                                break;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Invalid input, please try again.");
                    }
                }

                BREAK:;
            }
        }

        private static void loadCreateBasicKeys() {
            Console.WriteLine("Generating a random key...");
            Console.WriteLine("==============================================");
            Console.WriteLine("Please save all the data below!");
            Console.WriteLine("");

            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            byte[] random = new byte[4096];
            provider.GetBytes(random);
            string jibberish = Encoding.Unicode.GetString(random);

            if (jibberish != null)
            {
                // Step 1: String => Byte[] => SHA256 Byte[]
                // Compute the jibberish
                byte[] sha256jibberish = BitcoinKeyHelper.Sha256(Encoding.Unicode.GetBytes(jibberish));

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
                Console.WriteLine("==============================================");
                Console.WriteLine("Once you're done, simply enter any key to return to the menu.");

                Console.ReadKey();
            }
        }
    }
}
