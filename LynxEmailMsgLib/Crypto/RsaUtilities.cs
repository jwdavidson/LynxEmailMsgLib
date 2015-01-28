using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LynxEmailMsgLib.Crypto
{
    public static class RsaUtilities
    {
        public static byte[] CreateSignature(byte[] dataToSign, X509Certificate2 originatorCert)
        {
            byte[] signature;
            using (RSACryptoServiceProvider privateKp = (RSACryptoServiceProvider)originatorCert.PrivateKey) {
                using (SHA512Managed shaManaged = new SHA512Managed()) {

                    byte[] hashResult = shaManaged.ComputeHash(dataToSign);
                    signature = privateKp.SignData(hashResult, HashAlgorithm.Create("SHA512"));
                }
            }
            return signature;
        }

        public static bool ValidateSignature(byte[] dataToVerify, byte[] signature, X509Certificate2 originatorPublicCert)
        {
            bool valid = false;
            using (RSACryptoServiceProvider publicKp = (RSACryptoServiceProvider)originatorPublicCert.PublicKey.Key) {
                using (SHA512Managed shaManaged = new SHA512Managed()){
                    byte[] hashResult = shaManaged.ComputeHash(dataToVerify);
                    valid = publicKp.VerifyData(hashResult, HashAlgorithm.Create("SHA512"), signature);
                }
            }
            return valid;
        }
    }
}
