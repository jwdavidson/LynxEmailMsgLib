using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LynxEmailMsgLib.Crypto;

namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class UnitTest_AttachmentUtilitiesTest
    {
        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            X509Certificate2 gmailCert = StoreUtilities.FindCertBy(StoreName.Root, StoreLocation.CurrentUser, StoreUtilities.SupportedFindTypes.ByName, "jwdavidson@gmail.com");
            X509Certificate2 macCert = StoreUtilities.FindCertBy(StoreName.Root, StoreLocation.CurrentUser, StoreUtilities.SupportedFindTypes.ByName, "jw_davidson@me.com");
            if (gmailCert == null || gmailCert.SubjectName == null) {
                gmailCert = CertificateUtilities.BuildCertificate(CertificateUtilities.CertificateUse.Client, "jwdavidson@gmail.com");
                bool valid = StoreUtilities.StoreCert(StoreName.Root, StoreLocation.CurrentUser, gmailCert);
            }
            if (macCert == null || macCert.SubjectName == null) {
                macCert = CertificateUtilities.BuildCertificate(CertificateUtilities.CertificateUse.Client, "jw_davidson@me.com");
                bool valid = StoreUtilities.StoreCert(StoreName.Root, StoreLocation.CurrentUser, macCert);
            }

        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod1_CreateEncryptedAttachmentsArg1()
        {
            int cntProcessed = AttachmentUtilities.CreateEncryptedAttachments(null, "testEmail", new List<string> { "recipientEmail" });
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod2_CreateEncryptedAttachmentsArg2()
        {
            int cntProcessed = AttachmentUtilities.CreateEncryptedAttachments("fileName", null, new List<string> { "recipientEmail" });
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod3_CreateEncryptedAttachmentsArg3()
        {
            int cntProcessed = AttachmentUtilities.CreateEncryptedAttachments("fileName", "testEmail", new List<string> { });
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod4_CreateEncryptedAttachmentsArg3()
        {
            int cntProcessed = AttachmentUtilities.CreateEncryptedAttachments("fileName", "testEmail", null);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod5_CreateEncryptedAttachmentsArg2()
        {
            bool success = AttachmentUtilities.CreateEncryptedAttachment("fileName", null, "testEmail", "recipientEmail");
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod6_CreateEncryptedAttachmentsArg3()
        {
            bool success = AttachmentUtilities.CreateEncryptedAttachment("fileName", new byte[] {101, 99}, null, "recipientEmail");
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod7_CreateEncryptedAttachmentsArg4()
        {
            bool success = AttachmentUtilities.CreateEncryptedAttachment("fileName", new byte[] {101, 99 }, "testEmail", null);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod8_CreateDecryptedFileArg1()
        {
            bool success = AttachmentUtilities.CreateDecryptedFile(null);
        }

        [TestMethod]
        public void TestMethod9_CreateEncryptedAttachment()
        {
            string fileName = @"C:\Users\John\Documents\Test XML.docx";
            int cntEmail = AttachmentUtilities.CreateEncryptedAttachments(fileName, "jwdavidson@gmail.com", new List<string> {"jw_davidson@me.com"});
            Assert.IsTrue(cntEmail == 1);
        }

        [TestMethod]
        public void TestMethod10_CreateDecryptedFile()
        {
            bool valid = AttachmentUtilities.CreateDecryptedFile(@"C:\Test XML_docx_jw_davidson@me_com.xml");
            Assert.IsTrue(valid);
        }
        internal static unsafe SecureString CreateSecureString(char[] arrPassPhrase)
        {
            SecureString passPhrase;

            fixed (char* pChars = arrPassPhrase)
                passPhrase = new SecureString(pChars, arrPassPhrase.Length);

            passPhrase.MakeReadOnly();

            return passPhrase;
        }
    }
}
