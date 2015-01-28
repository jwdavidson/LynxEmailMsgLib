using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LynxEmailMsgLib.Crypto;

namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class UnitTest_RsaUtilitiesTest
    {

        internal static X509Certificate2 testCert;

        [TestInitialize]
        public void TestInit()
        {
            testCert = CertificateUtilities.BuildCertificate(CertificateUtilities.CertificateUse.RootServer, "TestRsaUtilities");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod1_ValidateCreateSignatureArg1()
        {
            byte[] signature = RsaUtilities.CreateSignature(null, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod2_ValidateCreateSignatureArg2()
        {
            testCert = null;
            byte[] signature = RsaUtilities.CreateSignature(new byte[] { 126, 85 }, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void TestMethod3_ValidateCreateSignatureArg2()
        {
            testCert = new X509Certificate2();
            byte[] signature = RsaUtilities.CreateSignature(new byte[] { 126, 85 }, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod4_ValidateValidateSignatureArg1()
        {
            bool valid = RsaUtilities.ValidateSignature(null, new byte[] { 126, 85 }, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod5_ValidateValidateSignatureArg2()
        {
            bool valid = RsaUtilities.ValidateSignature(new byte[] { 126, 85 }, null, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod6_ValidateValidateSignatureArg3()
        {
            testCert = null;
            bool valid = RsaUtilities.ValidateSignature(new byte[] { 126, 85 }, new byte[] { 125, 54 }, testCert);
        }
        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void TestMethod7_ValidateValidateSignatureArg3()
        {
            testCert = new X509Certificate2();
            bool valid = RsaUtilities.ValidateSignature(new byte[] { 126, 85 }, new byte[] { 125, 54 }, testCert);
        }

        [TestMethod]
        public void TestMethod8_SignAndVerifySha512Hash()
        {
            RSACryptoServiceProvider privateKp = (RSACryptoServiceProvider)testCert.PrivateKey;
            byte[] bytesToHash = Encoding.UTF8.GetBytes("This is a string to sign");
            SHA512Managed shaM = new SHA512Managed();
            byte[] hashResult = shaM.ComputeHash(bytesToHash);

            byte[] signature = privateKp.SignData(hashResult, HashAlgorithm.Create("SHA512"));
            Assert.IsNotNull(signature);
            Assert.IsTrue(signature.Length > 0);

            RSACryptoServiceProvider publicKp = (RSACryptoServiceProvider)testCert.PublicKey.Key;
            bool validSignature = publicKp.VerifyData(hashResult, HashAlgorithm.Create("SHA512"), signature);
            Assert.IsTrue(validSignature);
        }

        [TestMethod]
        public void TestMethod9_SignAndVerifySha512HashFail()
        {
            RSACryptoServiceProvider privateKp = (RSACryptoServiceProvider)testCert.PrivateKey;
            byte[] bytesToHash = Encoding.UTF8.GetBytes("This is a string to sign");
            SHA512Managed shaM = new SHA512Managed();
            byte[] hashResult = shaM.ComputeHash(bytesToHash);

            byte[] signature = privateKp.SignData(hashResult, HashAlgorithm.Create("SHA512"));
            Assert.IsNotNull(signature);
            Assert.IsTrue(signature.Length > 0);

            RSACryptoServiceProvider publicKp = (RSACryptoServiceProvider)testCert.PublicKey.Key;
            bool validSignature = publicKp.VerifyData(bytesToHash, HashAlgorithm.Create("SHA512"), signature);
            Assert.IsFalse(validSignature);
        }

        [TestCleanup]
        public void TestCleanup()
        {
            testCert = null;
        }
    }
}
