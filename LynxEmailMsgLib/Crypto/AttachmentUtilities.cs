using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace LynxEmailMsgLib.Crypto
{
    public static class AttachmentUtilities
    {
        // I may add more to this list like doc, docx, pdf, zip??
        private static string findRgx = @"\.(?<ext>(ad|adp|crt|ins|mdb|mde|msp|sct|shb|vb|wsc|wsf|cpl|shs|vsd|vst|vss|vsw|asp|bas|bat|chm|cmd|com|exe|hlp|hta|inf|isp|js|jse|lnk|msi|mst|pcd|pif|reg|scr|url|vbe|vbs|ws|wsh))";
        private static string replace = @"_(${ext}).txt";

        public static int CreateEncryptedAttachments(string fileToEncrypt, string originatorEmail, List<string> recipientEmailAddresses)
        {
            if (string.IsNullOrEmpty(fileToEncrypt))
                throw new ArgumentNullException("fileToEncrypt");
            if (string.IsNullOrEmpty(originatorEmail))
                throw new ArgumentNullException("originatorEmail");
            if (recipientEmailAddresses == null || recipientEmailAddresses.Count <= 0)
                throw new ArgumentNullException("recipientEmailAddresses");

            int countEmailsProcessed = 0;
            byte[] bytesToEncrypt = File.ReadAllBytes(fileToEncrypt);

            Regex.Replace(fileToEncrypt, findRgx, replace, RegexOptions.Compiled | RegexOptions.IgnoreCase);

            foreach (string recipientEmail in recipientEmailAddresses) {
                bool encryptedOk = CreateEncryptedAttachment(fileToEncrypt.Substring(fileToEncrypt.LastIndexOf(@"\")), bytesToEncrypt, originatorEmail, recipientEmail);
                if (encryptedOk) countEmailsProcessed++;
            }

            //manage unsafe file extensions and store in attachmentFileName for encryption - to leak as little data as possible

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

            try {
                X509Certificate2 origCert = StoreUtilities.FindCertBy(StoreName.Root, StoreLocation.CurrentUser, StoreUtilities.SupportedFindTypes.ByName, originatorEmail);
                X509Certificate2 recipientCert = StoreUtilities.FindCertBy(StoreName.Root, StoreLocation.CurrentUser, StoreUtilities.SupportedFindTypes.ByName, recipientEmail);

                recipientEmail = recipientEmail.Replace(".", "_");

                byte[] originatorCertRawData = origCert.RawData;
                string recipientThumbprint = recipientCert.Thumbprint;
                byte[] signature = RsaUtilities.CreateSignature(bytesToEncrypt, origCert);

                SymmetricKey aesKey = new SymmetricKey();

                StringBuilder toEncrypt = new StringBuilder();
                toEncrypt.Append("<CipherText><PlainText>");
                toEncrypt.Append(Convert.ToBase64String(bytesToEncrypt));
                toEncrypt.AppendLine("</PlainText>");
                toEncrypt.AppendLine("<SafeFileName>" + attachmentFileName + "</SafeFileName>");
                toEncrypt.AppendLine("<Signature>" + Convert.ToBase64String(signature) + "</Signature></CipherText>");

                byte[] cipherText = AesUtilities.EncryptStringToByteArray(toEncrypt.ToString(), aesKey.Key, aesKey.IV);

                byte[] encryptedAesData = RsaUtilities.EncryptDataPublicKey(aesKey.Key, aesKey.IV, recipientCert);
                byte[] encryptedAesKey = encryptedAesData.Take(512).ToArray();
                byte[] encryptedAesIV = encryptedAesData.Skip(512).ToArray();

                XDocument doc = new XDocument(
                    new XDeclaration("1.0", "utf-8", null),
                    new XElement("Root",
                        new XElement("OriginatorCertificate", Convert.ToBase64String(originatorCertRawData)),
                        new XElement("RecipientCertThumbprint", recipientThumbprint),
                        new XElement("EncryptedCipherText", Convert.ToBase64String(cipherText)),
                        new XElement("SymmetricKey",
                            new XElement("EncryptedAesKey", Convert.ToBase64String(encryptedAesKey)),
                            new XElement("EncryptedAesIV", Convert.ToBase64String(encryptedAesIV)))));

                doc.Save(attachmentFileName.Replace(".", "_") + "_" + recipientEmail + ".xml");
                success = true;
            }
            catch {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return success;
        }

        public static bool CreateDecryptedFile(string fileToDecrypt)
        {
            if (string.IsNullOrEmpty(fileToDecrypt))
                throw new ArgumentNullException("fileToDecrypt");

            bool success = false;

            try {
                XElement encryptedFile = XElement.Load(fileToDecrypt);

                byte[] originatorCertRawData = Convert.FromBase64String(encryptedFile.Elements().Where(e => e.Name.LocalName == "OriginatorCertificate").Single().Value);
                string recipientThumbprint = encryptedFile.Elements().Where(e => e.Name.LocalName == "RecipientCertThumbprint").Single().Value;
                byte[] cipherText = Convert.FromBase64String(encryptedFile.Elements().Where(e => e.Name.LocalName == "EncryptedCipherText").Single().Value);

                XElement symKeyElement = encryptedFile.Elements().Where(e => e.Name.LocalName == "SymmetricKey").Single();
                byte[] encryptedAesKey = Convert.FromBase64String(symKeyElement.Elements().Where(e => e.Name.LocalName == "EncryptedAesKey").Single().Value);
                byte[] encryptedAesKIV = Convert.FromBase64String(symKeyElement.Elements().Where(e => e.Name.LocalName == "EncryptedAesIV").Single().Value);

                X509Certificate2 recipientCert = StoreUtilities.FindCertBy(StoreName.Root, StoreLocation.CurrentUser, StoreUtilities.SupportedFindTypes.ByThumbprint, recipientThumbprint);
                byte[] decryptedSymKey = RsaUtilities.DecryptDataPrivateKey(encryptedAesKey, encryptedAesKIV, recipientCert);

                byte[] aesKey = decryptedSymKey.Take(32).ToArray();
                byte[] aesIV = decryptedSymKey.Skip(32).ToArray();

                string decryptedCipherText = AesUtilities.DecryptByteArrayToString(cipherText, aesKey, aesIV);

                XElement decryptedText = XElement.Parse(decryptedCipherText);
                byte[] plaintext = Convert.FromBase64String(decryptedText.Elements().Where(e => e.Name.LocalName == "PlainText").Single().Value);
                string safeFileName = decryptedText.Elements().Where(e => e.Name.LocalName == "SafeFileName").Single().Value;
                byte[] signature = Convert.FromBase64String(decryptedText.Elements().Where(e => e.Name.LocalName == "Signature").Single().Value);

                //may need to implement a bypass to allow for file creation even though this fails
                //or the file write may be placed before the signature validation
                File.WriteAllBytes(safeFileName, plaintext);

                bool validSignature = RsaUtilities.ValidateSignature(plaintext, signature, new X509Certificate2(originatorCertRawData));
                if (!validSignature)
                    throw new Exception("Data Signature fails validation. Consider deleting file created.");

                success = true;
            }
            catch {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return success;
        }
    }
}
