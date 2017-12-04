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
        public BitcoreSignatureHelper() {}

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

            string message = String.Join('|', reqList);

            return SignMessage(message, privKey);
        }
            
        private string SignMessage(string msg, string privKey)
        {
            //$.checkArgument(text);
            string hashMsg = DoubleHashMessageReverse(msg);

            // Retrieve the private key in bigint
            BigInteger privateKeyInt = new BigInteger(+1, Encoding.Unicode.GetBytes(privKey));

            // Reconstruct the curve
            X9ECParameters parameters = SecNamedCurves.GetByName("secp256k1");
            Org.BouncyCastle.Math.EC.ECPoint point = parameters.G.Multiply(privateKeyInt);

            // Setup the signer
            // https://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.crypto.signers.ECDSASigner
            ECDsaSigner signer = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));

            // Construct the ECDomainParameters
            // https://programtalk.com/java-api-usage-examples/org.bouncycastle.crypto.params.ECDomainParameters/ => How to get the parameters
            ECDomainParameters ecDomainParams = new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H);

            signer.Init(true, new ECPrivateKeyParameters(privateKeyInt, ecDomainParams));
            BigInteger[] signature = signer.GenerateSignature(Encoding.Unicode.GetBytes(hashMsg));

            // https://stackoverflow.com/questions/37572306/verifying-ecdsa-signature-with-bouncy-castle-in-c-sharp
            MemoryStream stream = new MemoryStream();
            DerOutputStream der = new DerOutputStream(stream);
            try
            {
                Asn1EncodableVector seq = new Asn1EncodableVector();
                seq.Add(new DerInteger(signature[0]));
                seq.Add(new DerInteger(signature[1]));
                der.WriteObject(new DerSequence(seq));

                return Encoding.Unicode.GetString(stream.ToArray());
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
            for (int i = 0; i < inputArr.Length; i++) {
                resultChars[i] = inputArr[inputArr.Length - 1 - i];
            }

            return resultChars.ToString();
        }
    }
}
