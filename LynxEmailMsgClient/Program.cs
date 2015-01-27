//
// This code was written by Keith Brown, and may be freely used.
// Want to learn more about .NET? Visit pluralsight.com today!
//
using System;
using System.Diagnostics;
using System.Windows.Forms;
using LynxEmailMsgLib.Crypto;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LynxEmailMsgClient
{
    class Program
    {
        static void Main(string[] args)
        {

            CryptoConfig.AddOID("1.3.6.1.4.1.45177.1.1", new string[] { "LynxEmailSystemServerCommunications Root Server" });

            var CA = CreateCertificateAuthority();

            Console.WriteLine("CA: " + CA);

            bool success = LynxEmailMsgLib.Crypto.Utilities.StoreCert(StoreName.Root, StoreLocation.LocalMachine, CA);

            //var subordinate = CreateSubordinate();

            //Console.WriteLine("Subordinate: " + subordinate);

            //var signedSubordinate = SignIt(subordinate, CA);

            //Console.WriteLine("Signed: " + signedSubordinate);

            Console.Write("Press enter to close...");

            Console.ReadLine();
        }

        private static X509Certificate2 SignIt(X509Certificate2 subordinate, X509Certificate2 CA)
        {
            var csr = new CertificateSigningRequest() {
                KeySpecification = CertificateSigner.AT_SIGNATURE,
                Certificate = subordinate,
                ExpirationLength = subordinate.NotAfter - subordinate.NotBefore
            };

            return CertificateSigner.SignCertificate(csr, CA);
        }

        private static X509Certificate2 CreateCertificateAuthority()
        {
            CspParameters parameters = new CspParameters() {
                ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
                ProviderType = 24,
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = (int)KeyNumber.Signature,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            var oids = new OidCollection();
            oids.Add(new Oid("1.3.6.1.4.1.45177.1.1", "LynxEmailSystemServerCommunications Root Server"));

            var extensions = new X509ExtensionCollection();

            extensions.Add(new X509BasicConstraintsExtension(false, true, 1, false));
            extensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DataEncipherment |
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.KeyAgreement |
                X509KeyUsageFlags.KeyCertSign |
                X509KeyUsageFlags.KeyEncipherment |
                X509KeyUsageFlags.NonRepudiation, false));
            extensions.Add(new X509EnhancedKeyUsageExtension(oids, true));

            var cgr = new CertificateGenerationRequest() {
                Subject = "LynxEmailSysSvr_2001:470:1d:80b:e5b6:2d69:3897:336a",
                Parameters = parameters,
                SignatureAlgorithm = "1.2.840.113549.1.1.13",  // szOID_RSA_SHA512RSA
                ExpirationLength = TimeSpan.FromDays(365 * 5),
                KeySize = 4096,
                Extensions = extensions
            };

            var cert = CertificateGenerator.CreateSelfSignedCertificate(cgr);
            return cert;
        }

        private static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateSubordinate()
        {
            var oids = new OidCollection();
            oids.Add(new Oid("1.3.6.1.5.5.7.3.2")); // client auth
            oids.Add(new Oid("1.3.6.1.4.1.311.20.2.2")); // smart card login

            var extensions = new X509ExtensionCollection();
            extensions.Add(new X509EnhancedKeyUsageExtension(oids, true));

            var cgr = new CertificateGenerationRequest() {
                Subject = "steve@syfuhs.net",
                Extensions = extensions,
                ExpirationLength = TimeSpan.FromDays(365 * 5),
                KeySize = 2048
            };

            var cert = CertificateGenerator.CreateSelfSignedCertificate(cgr);
            return cert;
        }


    }
}
