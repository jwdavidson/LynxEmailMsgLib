using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LynxEmailMsgLib.Crypto;
using LynxEmailMsgClient;

namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class FindCertificatesTest
    {
        [TestMethod]
        public void TestMethod1_FindRootServerCertificateByName()
        {
            SvrProperties svrProps = new SvrProperties();
            X509Certificate2 svrCert = Utilities.FindCertByName(StoreName.Root, StoreLocation.LocalMachine, svrProps.RootServer);

            Assert.IsNotNull(svrCert);
            Assert.IsTrue(svrCert.SubjectName.Name == "CN=" + svrProps.RootServer);
        }

        [TestMethod]
        public void TestMethod2_FindRootServerCertificatebyOID()
        {
            SvrProperties svrProps = new SvrProperties();
            X509Certificate2Collection svrCerts = Utilities.FindCertsByOID(StoreName.Root, StoreLocation.LocalMachine, svrProps.RootServerOID);

            Assert.IsNotNull(svrCerts);
            Assert.IsTrue(svrCerts.Count == 1);

            X509Certificate2 svrCert = svrCerts[0];
            Assert.IsTrue(svrCert.SubjectName.Name == "CN=" + svrProps.RootServer);
        }
        [TestMethod]
        public void TestMethod2_InitKeyProvidersFromCert()
        {
            SvrProperties svrProps = new SvrProperties();
            X509Certificate2 svrCert = Utilities.FindCertByName(StoreName.Root, StoreLocation.LocalMachine, svrProps.RootServer);

            Assert.IsNotNull(svrCert);
            Assert.IsTrue(svrCert.SubjectName.Name == "CN=" + svrProps.RootServer);

            RSACryptoServiceProvider publicKp = (RSACryptoServiceProvider)svrCert.PublicKey.Key;
            Assert.IsInstanceOfType(publicKp, typeof(RSACryptoServiceProvider));
            RSACryptoServiceProvider privateKp = (RSACryptoServiceProvider)svrCert.PrivateKey;
            Assert.IsInstanceOfType(privateKp, typeof(RSACryptoServiceProvider));

            Assert.IsTrue(publicKp.KeySize == 4096);
            Assert.IsTrue(privateKp.KeySize == 4096);

        }

        [TestMethod]
        public void TestMethod4_InitX509FromRawData()
        {
            SvrProperties svrProps = new SvrProperties();
            X509Certificate2Collection svrCerts = Utilities.FindCertsByOID(StoreName.Root, StoreLocation.LocalMachine, svrProps.RootServerOID);

            Assert.IsNotNull(svrCerts);
            Assert.IsTrue(svrCerts.Count == 1);

            X509Certificate2 svrCert = svrCerts[0];
            Assert.IsTrue(svrCert.SubjectName.Name == "CN=" + svrProps.RootServer);

            X509Certificate2 newCert = new X509Certificate2(svrCert.RawData);

            Assert.IsTrue(newCert.SubjectName.Name == "CN=" + svrProps.RootServer);
            Assert.IsTrue(newCert.Thumbprint == svrCert.Thumbprint);
        }
    }
}
