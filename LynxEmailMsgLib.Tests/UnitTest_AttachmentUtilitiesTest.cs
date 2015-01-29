using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LynxEmailMsgLib.Crypto;

namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class UnitTest_AttachmentUtilitiesTest
    {
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
    }
}
