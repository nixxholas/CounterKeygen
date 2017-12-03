using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Sec;

namespace CounterKeygen.Helpers
{
    public class BitcoinKeyHelper
    {
        static SHA256Managed _hashstring = new SHA256Managed();

        public static byte[] GeneratePublicKey(byte[] privateKey)
        {
            Org.BouncyCastle.Math.BigInteger privateKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, privateKey);

            var parameters = SecNamedCurves.GetByName("secp256k1");
            Org.BouncyCastle.Math.EC.ECPoint point = parameters.G.Multiply(privateKeyInt);

            byte[] pubKeyX = point.X.ToBigInteger().ToByteArrayUnsigned();
            //byte[] pubKeyY = point.Y.ToBigInteger().ToByteArrayUnsigned();

            byte[] pubKey = new byte[pubKeyX.Length + 1];

            // Copy pub key X over to pubKey
            pubKeyX.CopyTo(pubKey, 1);

            // Setup the parity byte
            if (point.Y.ToBigInteger().Mod(new Org.BouncyCastle.Math.BigInteger("2")) == new Org.BouncyCastle.Math.BigInteger("1")) {
                pubKey[0] = 0x03;
            } else {
                pubKey[0] = 0x02;
            }

            // Return the public key
            //return Tuple.Create(pubKeyX, pubKeyY);
            return pubKey;
        }

        public static string CreateAddress(string PublicKey)
        {
            byte[] Hash = AppendToBitcoinNetwork(RipeMD160(Sha256(HexToByte(PublicKey))), 0);
            return Base58Encode(ConcatAddress(Hash, Sha256(Sha256(Hash))));
        }

        /// <summary>
        /// The general C++ ported function of Base58 Encoding.
        /// </summary>
        /// <param name="array"></param>
        /// <returns></returns>
        public static string Base58Encode(byte[] array)
        {
            const string CHARACTERS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            string retString = string.Empty;
            System.Numerics.BigInteger encodeSize = CHARACTERS.Length;
            System.Numerics.BigInteger arrayToInt = 0;
            for (int i = 0; i < array.Length; ++i)
            {
                arrayToInt = arrayToInt * 256 + array[i];
            }
            while (arrayToInt > 0)
            {
                int rem = (int)(arrayToInt % encodeSize);
                arrayToInt /= encodeSize;
                retString = CHARACTERS[rem] + retString;
            }
            for (int i = 0; i < array.Length && array[i] == 0; ++i)
                retString = CHARACTERS[0] + retString;

            return retString;
        }

        /// <summary>
        /// Converts the Hexidecimal string to a byte array, it’s simple as taking the 2 characters and converting it into base 256
        /// </summary>
        /// <param name="HexString"></param>
        /// <returns></returns>
        public static byte[] HexToByte(string HexString)
        {
            if (HexString.Length % 2 != 0)
                throw new Exception("Invalid HEX");
            byte[] retArray = new byte[HexString.Length / 2];
            for (int i = 0; i < retArray.Length; ++i)
            {
                retArray[i] = byte.Parse(HexString.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return retArray;
        }

        /// <summary>
        /// Sha256 uses Microsoft’s security cryptography include, and by default takes a byte array
        /// </summary>
        /// <param name="array"></param>
        /// <returns></returns>
        public static byte[] Sha256(byte[] array)
        {
            return _hashstring.ComputeHash(array);
        }

        /// <summary>
        /// Sha256s the string
        /// </summary>
        /// <returns>The hash.</returns>
        /// <param name="value">Value.</param>
        public static string Sha256ByString(string value)
        {
            StringBuilder Sb = new StringBuilder();

            using (var hash = SHA256.Create())
            {
                Encoding enc = Encoding.UTF8;
                Byte[] result = hash.ComputeHash(enc.GetBytes(value));

                foreach (Byte b in result)
                    Sb.Append(b.ToString("x2"));
            }

            return Sb.ToString();
        }

        /// <summary>
        /// Again this function uses Microsoft’s security cryptography include and is pretty much identical to the Sha256 function.
        /// </summary>
        /// <param name="array"></param>
        /// <returns></returns>
        public static byte[] RipeMD160(byte[] array)
        {
            RIPEMD160Managed hashstring = new RIPEMD160Managed();
            return hashstring.ComputeHash(array);
        }

        /// <summary>
        /// Appends the last 4 bytes of the hash onto the end of the RipeMD160 value
        /// </summary>
        /// <param name="RipeHash"></param>
        /// <param name="Checksum"></param>
        /// <returns></returns>
        public static byte[] ConcatAddress(byte[] RipeHash, byte[] Checksum)
        {
            byte[] ret = new byte[RipeHash.Length + 4];
            Array.Copy(RipeHash, ret, RipeHash.Length);
            Array.Copy(Checksum, 0, ret, RipeHash.Length, 4);
            return ret;
        }

        /// <summary>
        /// Pre-appends a byte onto the beginning of an array of bytes
        /// </summary>
        /// <param name="RipeHash"></param>
        /// <param name="Network"></param>
        /// <returns></returns>
        public static byte[] AppendToBitcoinNetwork(byte[] RipeHash, byte Network)
        {
            byte[] extended = new byte[RipeHash.Length + 1];
            extended[0] = (byte)Network;
            Array.Copy(RipeHash, 0, extended, 1, RipeHash.Length);
            return extended;
        }
    }
}
