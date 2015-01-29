using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

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

        public static bool CreateEncryptedAttachment(string attachmentFileName, byte[] bytesToEncrypt, string originatorEmail, string recipientEmail)
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

            byte[] encryptedAesData = RsaUtilities.EncryptDataPublicKey(aesKey.Key, aesKey.IV, recipientCert);
            byte[] encryptedAesKey = encryptedAesData.Take(512).ToArray();
            byte[] encryptedAesIV = encryptedAesData.Skip(512).ToArray();

            XDocument doc = new XDocument(
                new XDeclaration("1.0", "utf-16", "true"),
                new XElement("OriginatorCertificate", Convert.ToBase64String(originatorCertRawData)),
                new XElement("RecipientCertThumbprint", recipientThumbprint),
                new XElement("cipherText", Convert.ToBase64String(cipherText)),
                new XElement("SymmetricKey",
                    new XElement("EncryptedAesKey", Convert.ToBase64String(encryptedAesKey)),
                    new XElement("EncryptedAesIV", Convert.ToBase64String(encryptedAesIV))));

            doc.Save(attachmentFileName + "_" + recipientEmail + ".xml");

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
