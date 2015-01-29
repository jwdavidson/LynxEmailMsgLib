using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace LynxEmailMsgLib.Crypto
{
    public static class AttachmentUtilities
    {
        public static int CreateEncryptedAttachments(string fileToEncrypt, string originatorEmail, List<string> recipientEmailAddresses)
        {
            if (string.IsNullOrEmpty(fileToEncrypt))
                throw new ArgumentNullException("fileToEncrypt");
            if (string.IsNullOrEmpty(originatorEmail))
                throw new ArgumentNullException("originatorEmail");
            if (recipientEmailAddresses == null || recipientEmailAddresses.Count <= 0)
                throw new ArgumentNullException("recipientEmailAddresses");

            int countEmailsProcessed = 0;

            return countEmailsProcessed;
        }

        public static bool CreateEncryptedAttachment(byte[] bytesToEncrypt, string originatorEmail, string recipientEmail)
        {
            if (bytesToEncrypt == null || bytesToEncrypt.Length <= 0)
                throw new ArgumentNullException("bytesToEncrypt");
            if (string.IsNullOrEmpty(originatorEmail))
                throw new ArgumentNullException("originatorEmail");
            if (string.IsNullOrEmpty(recipientEmail))
                throw new ArgumentNullException("recipientEmail");

            bool success = false;

            X509Certificate2 origCert = StoreUtilities.FindCertBy(StoreName.Root, StoreLocation.CurrentUser, StoreUtilities.SupportedFindTypes.ByName, originatorEmail);
            X509Certificate2 recipientCert = StoreUtilities.FindCertBy(StoreName.My, StoreLocation.CurrentUser, StoreUtilities.SupportedFindTypes.ByName, recipientEmail);


            byte[] originatorCertRawData = origCert.RawData;
            string recipientThumbprint = recipientCert.Thumbprint;
            byte[] signature = RsaUtilities.CreateSignature(bytesToEncrypt, origCert);

            SymmetricKey aesKey = new SymmetricKey();

            StringBuilder toEncrypt = new StringBuilder();
            toEncrypt.Append("<PlainText>");
            toEncrypt.Append(Convert.ToBase64String(bytesToEncrypt));
            toEncrypt.AppendLine("</PlainText>");
            toEncrypt.AppendLine("<Signature>" + Convert.ToBase64String(signature) + "</Signature>");

            byte[] cipherText = AesUtilities.EncryptStringToByteArray(toEncrypt.ToString(), aesKey.Key, aesKey.IV);

            StringBuilder symmetricKey = new StringBuilder();
            symmetricKey.AppendLine("<SymmetricKey>");
            symmetricKey.AppendLine("<Key>" + Convert.ToBase64String(aesKey.Key) + "</Key>");
            symmetricKey.AppendLine("<IV>" + Convert.ToBase64String(aesKey.IV) + "</IV>");
            symmetricKey.AppendLine("</SymmetricKey>");

            //byte[] encryptedSymmetricKey = RsaUtilities.EncryptDataPublicKey(symmetricKey.ToString(), recipientCert);

            return success;
        }

        public static bool CreateDecryptedFile(string fileToDecrypt, string originatorEmail, string recipientEmail)
        {
            if (string.IsNullOrEmpty(fileToDecrypt))
                throw new ArgumentNullException("fileToDecrypt");
            if (string.IsNullOrEmpty(originatorEmail))
                throw new ArgumentNullException("originatorEmail");
            if (string.IsNullOrEmpty(recipientEmail))
                throw new ArgumentNullException("recipientEmail");

            bool success = false;

            return success;
        }
    }
}
