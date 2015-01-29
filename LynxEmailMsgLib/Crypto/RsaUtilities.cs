using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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

            byte[] signature = null;
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

        public static byte[] EncryptDataPublicKey(byte[] dataKeyToEncrypt, byte[] dataIVToEncrypt, X509Certificate2 recipientCert)
        {
            if (dataKeyToEncrypt == null || dataKeyToEncrypt.Length <= 0)
                throw new ArgumentNullException("dataKeyToEncrypt");
            if (dataIVToEncrypt == null || dataIVToEncrypt.Length <= 0)
                throw new ArgumentNullException("dataIVToEncrypt");
            if (recipientCert == null)
                throw new ArgumentNullException("recipientCert");
            if (recipientCert.RawData == null || recipientCert.RawData.Length <= 0)
                throw new CryptographicException("recipientCert.RawData");

            byte[] encryptedData;

            using (RSACryptoServiceProvider publicKp = (RSACryptoServiceProvider)recipientCert.PublicKey.Key) {
                encryptedData = publicKp.Encrypt(dataKeyToEncrypt, true);
                encryptedData = encryptedData.Concat(publicKp.Encrypt(dataIVToEncrypt, true)).ToArray();
            }
            return encryptedData;
        }

        public static byte[] DecryptDataPrivateKey(byte[] dataKeyToDecrypt, byte[] dataIVToDecrypt, X509Certificate2 recipientCert)
        {
            if (dataKeyToDecrypt == null || dataKeyToDecrypt.Length <= 0)
                throw new ArgumentNullException("dataKeyToDecrypt");
            if (dataIVToDecrypt == null || dataIVToDecrypt.Length <= 0)
                throw new ArgumentNullException("dataIVToDecrypt");
            if (recipientCert == null)
                throw new ArgumentNullException("recipientCert");
            if (!recipientCert.HasPrivateKey)
                throw new CryptographicException("recipientCert.PrivateKey");

            byte[] decryptedData;

            using (RSACryptoServiceProvider privateKp = (RSACryptoServiceProvider)recipientCert.PrivateKey) {
                decryptedData = privateKp.Decrypt(dataKeyToDecrypt, true);
                decryptedData = decryptedData.Concat(privateKp.Decrypt(dataIVToDecrypt, true)).ToArray();
            }
            return decryptedData;
        }
    }
}
