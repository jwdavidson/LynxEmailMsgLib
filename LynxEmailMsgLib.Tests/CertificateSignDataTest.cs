using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LynxEmailMsgLib.Crypto;
using LynxEmailMsgClient;


namespace LynxEmailMsgLib.Tests
{
    [TestClass]
    public class CertificateSignDataTest
    {
        [TestMethod]
        public void TestMethod1_SignAndVerifyHash()
        {
            //const string sha512RSA = "1.2.840.113549.1.1.13";

            SvrProperties svrProps = new SvrProperties();
            X509Certificate2 svrCert = Utilities.FindCertByName(StoreName.Root, StoreLocation.LocalMachine, svrProps.RootServer);

            Assert.IsNotNull(svrCert);
            Assert.IsTrue(svrCert.SubjectName.Name == "CN=" + svrProps.RootServer);

            RSACryptoServiceProvider publicKp = (RSACryptoServiceProvider)svrCert.PublicKey.Key;

            RSACryptoServiceProvider privateKp = (RSACryptoServiceProvider)svrCert.PrivateKey;

            byte[] fileBytes = File.ReadAllBytes(@"C:\Users\John\Documents\Test XML.docx");
            SHA1 shaM = new SHA1Managed();
            byte[] fileResult = shaM.ComputeHash(fileBytes);

            byte[] signature = privateKp.SignHash(fileResult, null);

            bool validSignature = publicKp.VerifyHash(fileResult, null, signature);
            Assert.IsTrue(validSignature);

        }

        [TestMethod]
        public void TestMethod2_SignAndVerifyHash512()
        {
            //const string sha512RSA = "1.2.840.113549.1.1.13";

            SvrProperties svrProps = new SvrProperties();
            X509Certificate2 svrCert = Utilities.FindCertByName(StoreName.Root, StoreLocation.LocalMachine, svrProps.RootServer);

            Assert.IsNotNull(svrCert);
            Assert.IsTrue(svrCert.SubjectName.Name == "CN=" + svrProps.RootServer);

            RSACryptoServiceProvider publicKp = (RSACryptoServiceProvider)svrCert.PublicKey.Key;

            RSACryptoServiceProvider privateKp = (RSACryptoServiceProvider)svrCert.PrivateKey;

            byte[] fileBytes = File.ReadAllBytes(@"C:\Users\John\Documents\Test XML.docx");
            SHA512 shaM = new SHA512Managed();
            byte[] fileResult = shaM.ComputeHash(fileBytes);

            byte[] signature = privateKp.SignData(fileResult, HashAlgorithm.Create("SHA512"));

            bool validSignature = publicKp.VerifyData(fileResult, HashAlgorithm.Create("SHA512"), signature);
            Assert.IsTrue(validSignature);

        }
    }
}
