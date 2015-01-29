using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LynxEmailMsgLib.Crypto;
namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class UnitTest_RsaUtilitiesEncryptionTest
    {
        internal static X509Certificate2 testCert;

        [TestInitialize]
        public void TestInit()
        {
            testCert = CertificateUtilities.BuildCertificate(CertificateUtilities.CertificateUse.RootServer, "TestRsaUtilities");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod1_ValidateEncryptDataPublicKeyArg1()
        {
            byte[] encrypted = RsaUtilities.EncryptDataPublicKey(null, new byte[] { 99, 98 }, testCert);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod2_ValidateEncryptDataPublicKeyArg2()
        {
            testCert = null;
            byte[] encrypted = RsaUtilities.EncryptDataPublicKey(new byte[] { 99, 98 }, new byte[] { 99, 98 }, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod3_ValidateDecryptDataPrivateKeyArg1()
        {
            byte[] encrypted = RsaUtilities.DecryptDataPrivateKey(null, new byte[] { 99, 98 }, testCert);
        }
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod4_ValidateDecryptDataPrivateKeyArg2()
        {
            testCert = null;
            byte[] encrypted = RsaUtilities.DecryptDataPrivateKey(new byte[] { 99, 98 }, new byte[] { 99, 98 }, testCert);
        }
        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void TestMethod5_ValidateDecryptDataPrivateKeyArg2()
        {
            X509Certificate2 certWithoutPrivateKey = new X509Certificate2();
            certWithoutPrivateKey.Import(testCert.RawData);
            Assert.IsFalse(certWithoutPrivateKey.HasPrivateKey);

            byte[] encrypted = RsaUtilities.DecryptDataPrivateKey(new byte[] {99, 98 }, new byte[] {99, 98 }, certWithoutPrivateKey);
        }

        [TestMethod]
        public void TestMethod6_SymmetricKeyStorage()
        {

            SymmetricKey aesKey = new SymmetricKey();
            byte[] encryptedData = RsaUtilities.EncryptDataPublicKey(aesKey.Key, aesKey.IV, testCert);

            byte[] encryptedKey = encryptedData.Take(512).ToArray();
            byte[] encryptedIV = encryptedData.Skip(512).ToArray();

            //StringBuilder symmetricKey = new StringBuilder();
            //symmetricKey.AppendLine("<SymmetricKey>");
            //symmetricKey.AppendLine("<Key>" + Convert.ToBase64String(aesKey.Key) + "</Key>");
            //symmetricKey.AppendLine("<IV>" + Convert.ToBase64String(aesKey.IV) + "</IV>");
            //symmetricKey.AppendLine("</SymmetricKey>");

            byte[] decryptedData = RsaUtilities.DecryptDataPrivateKey(encryptedKey, encryptedIV, testCert);
            byte[] decryptedKey = decryptedData.Take(32).ToArray();
            byte[] decryptedIV = decryptedData.Skip(32).ToArray();

            Assert.IsTrue(aesKey.Key.SequenceEqual(decryptedKey));
            Assert.IsTrue(aesKey.IV.SequenceEqual(decryptedIV));

        }

    }
}
