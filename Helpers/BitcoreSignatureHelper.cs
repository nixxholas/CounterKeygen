using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CounterKeygen.Utils;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace CounterKeygen.Helpers
{
    public class BitcoreSignatureHelper
    {
        public BitcoreSignatureHelper() { }

        /// <summary>
        /// Signs the request.
        /// </summary>
        /// <returns>The request.</returns>
        /// <param name="method">The HTTP method</param>
        /// <param name="url">The URL for the request</param>
        /// <param name="args">The arguments in case this is a POST/PUT request</param>
        /// <param name="privKey">Master (If generating x-signature) XPrivate key to sign the request</param>
        public string SignRequest(string method, string url, string args, string privKey)
        {
            List<string> reqList = new List<string>();

            reqList.Add(method.ToLower());
            reqList.Add(url);
            reqList.Add(args);

            string message = string.Join('|', reqList);

            // Debugging only
            //Console.WriteLine("Concatenated Message: " + message);

            return SignMessage(message, privKey);
        }

        public string SignMessage(string msg, string privKey)
        {
            //$.checkArgument(text);
            string hashMsg = DoubleHashMessageReverse(msg);

            // Debugging Only
            //Console.WriteLine("Hashed Message: " + hashMsg);
            //Console.WriteLine("Hashed Message in Bytes: " + BitConverter.ToString(Encoding.Unicode.GetBytes(hashMsg)));
            byte[] bytedPrivKey = ConvertToByteArray(privKey);

            // Retrieve the private key in bigint
            BigInteger privateKeyInt = new BigInteger(+1, ConvertToByteArray(privKey));

            // Reconstruct the curve
            X9ECParameters parameters = SecNamedCurves.GetByName("secp256k1");
            //Org.BouncyCastle.Math.EC.ECPoint point = parameters.G.Multiply(privateKeyInt);

            // Setup the signer
            // https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.signers.ECDSASigner
            // Cant new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest())); Because Btc doesn't use those..
            ECDsaSigner signer = new ECDsaSigner();

            // Construct the ECDomainParameters
            // https://programtalk.com/java-api-usage-examples/org.bouncycastle.crypto.params.ECDomainParameters/ => How to get the parameters
            ECDomainParameters ecDomainParams = new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H);
            ECKeyParameters keyParams = new ECPrivateKeyParameters(privateKeyInt, ecDomainParams);

            signer.Init(true, keyParams);
            BigInteger[] signature = signer.GenerateSignature(Encoding.Unicode.GetBytes(hashMsg));

            // https://stackoverflow.com/questions/37572306/verifying-ecdsa-signature-with-bouncy-castle-in-c-sharp
            MemoryStream stream = new MemoryStream();
            //DerOutputStream der = new DerOutputStream(stream);

            try
            {
                //Asn1EncodableVector seq = new Asn1EncodableVector();
                //seq.Add(new DerInteger(signature[0]));
                //seq.Add(new DerInteger(signature[1]));
                //der.WriteObject(new DerSequence(seq));    
                DerSequenceGenerator seq = new DerSequenceGenerator(stream);
                seq.AddObject(new DerInteger(signature[0]));
                seq.AddObject(new DerInteger(signature[1]));
                seq.Close();

                byte[] bitResult = stream.ToArray();

                PrintByteArray(bitResult);

                Console.WriteLine("MemoryStream Output: " + BitConverter.ToString(bitResult).Replace("-", string.Empty));

                return BitConverter.ToString(bitResult).Replace("-", string.Empty);
            }
            catch (IOException e)
            {
                return e.ToString();
            }
        }

        private string DoubleHashMessageReverse(string msg)
        {
            if (msg == null) { return null; }
            return Reverse(SHA256Hash.Hash(SHA256Hash.Hash(msg)));
        }

        private string Reverse(string input)
        {
            // https://stackoverflow.com/questions/8047064/convert-string-to-system-io-stream
            //MemoryStream stream = new MemoryStream(Encoding.Unicode.GetBytes(input));
            //StreamReader reader = new StreamReader(stream);
            char[] inputArr = input.ToCharArray();
            char[] resultChars = new char[inputArr.Length];

            // https://stackoverflow.com/questions/11985348/read-and-output-a-text-file-using-streamreader-char-by-char
            for (int i = 0; i < inputArr.Length; i++)
            {
                resultChars[i] = inputArr[inputArr.Length - 1 - i];
            }

            return new string(resultChars);
        }

        #region ByteHelpers

        private static byte[] ConvertToByteArray(string value)
        {
            byte[] bytes = null;
            if (String.IsNullOrEmpty(value))
                bytes = new byte[0];
            else
            {
                int string_length = value.Length;
                int character_index = (value.StartsWith("0x", StringComparison.Ordinal)) ? 2 : 0; // Does the string define leading HEX indicator '0x'. Adjust starting index accordingly.               
                int number_of_characters = string_length - character_index;

                bool add_leading_zero = false;
                if (0 != (number_of_characters % 2))
                {
                    add_leading_zero = true;

                    number_of_characters += 1;  // Leading '0' has been striped from the string presentation.
                }

                bytes = new byte[number_of_characters / 2]; // Initialize our byte array to hold the converted string.

                int write_index = 0;
                if (add_leading_zero)
                {
                    bytes[write_index++] = FromCharacterToByte(value[character_index], character_index);
                    character_index += 1;
                }

                for (int read_index = character_index; read_index < value.Length; read_index += 2)
                {
                    byte upper = FromCharacterToByte(value[read_index], read_index, 4);
                    byte lower = FromCharacterToByte(value[read_index + 1], read_index + 1);

                    bytes[write_index++] = (byte)(upper | lower);
                }
            }

            return bytes;
        }

        private static byte FromCharacterToByte(char character, int index, int shift = 0)
        {
            byte value = (byte)character;
            if (((0x40 < value) && (0x47 > value)) || ((0x60 < value) && (0x67 > value)))
            {
                if (0x40 == (0x40 & value))
                {
                    if (0x20 == (0x20 & value))
                        value = (byte)(((value + 0xA) - 0x61) << shift);
                    else
                        value = (byte)(((value + 0xA) - 0x41) << shift);
                }
            }
            else if ((0x29 < value) && (0x40 > value))
                value = (byte)((value - 0x30) << shift);
            else
                throw new InvalidOperationException(String.Format("Character '{0}' at index '{1}' is not valid alphanumeric character.", character, index));

            return value;
        }

        public void PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("new byte[] { ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("}");
            Console.WriteLine(sb.ToString());
        }

        #endregion
    }
}
