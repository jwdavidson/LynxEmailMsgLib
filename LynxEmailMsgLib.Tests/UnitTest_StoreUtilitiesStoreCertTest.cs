using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LynxEmailMsgLib.Crypto;
namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class UnitTest_StoreUtilitiesStoreCertTest
    {
        internal static X509Certificate2 testCert;

        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            testCert = CertificateUtilities.BuildCertificate(CertificateUtilities.CertificateUse.RootServer, "RSTestFind");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void TestMethod1_ValidateStoreCertArg1()
        {
            bool valid = StoreUtilities.StoreCert((StoreName)(-1), StoreLocation.LocalMachine, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void TestMethod2_ValidateStoreCertArg1()
        {
            bool valid = StoreUtilities.StoreCert((StoreName)100, StoreLocation.LocalMachine, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void TestMethod3_ValidateStoreCertArg2()
        {
            bool valid = StoreUtilities.StoreCert(StoreName.Root, (StoreLocation)(-1), testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void TestMethod4_ValidateStoreCertArg2()
        {
            bool valid = StoreUtilities.StoreCert(StoreName.Root, (StoreLocation)100, testCert);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestMethod5_ValidateStoreCertArg3()
        {
            bool valid = StoreUtilities.StoreCert(StoreName.Root, StoreLocation.LocalMachine, null);
        }

        [TestMethod]
        public void TestMethod6_StoreCertTest()
        {
            bool valid = StoreUtilities.StoreCert(StoreName.Root, StoreLocation.LocalMachine, testCert);
            Assert.IsTrue(valid);
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            store.Remove(testCert);
            store.Close();
            testCert = null;
        }
    }
}
