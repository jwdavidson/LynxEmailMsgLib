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
            if (dataToSign == null || dataToSign.Length <= 0)
                throw new ArgumentNullException("dataToSign");
            if (originatorCert == null)
                throw new ArgumentNullException("originatorCert");
            if (originatorCert.RawData == null || originatorCert.RawData.Length <= 0)
                throw new CryptographicException("originatorCert.RawData");

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
            if (dataToVerify == null || dataToVerify.Length <= 0)
                throw new ArgumentNullException("dataToVerify");
            if (signature == null || signature.Length <= 0)
                throw new ArgumentNullException("signature");
            if (originatorPublicCert == null)
                throw new ArgumentNullException("originatorPublicCert");
            if (originatorPublicCert.RawData == null || originatorPublicCert.RawData.Length <= 0)
                throw new CryptographicException("originatorPublicCert.RawData");

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
