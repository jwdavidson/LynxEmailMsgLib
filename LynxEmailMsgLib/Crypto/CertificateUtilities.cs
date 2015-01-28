using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace LynxEmailMsgLib.Crypto
{
    public static class CertificateUtilities
    {
        public enum CertificateUse
        {
            RootServer,
            BackupRootServer,
            Server,
            Client
        }

        const string OID_RSA_SHA512RSA = "1.2.840.113549.1.1.13";
        public static X509Certificate2 BuildCertificate(CertificateUse usage, string subjectName)
        {
            if (usage == null)
                throw new ArgumentNullException("usage");
            if (!Enum.IsDefined(typeof(CertificateUse), usage))
                throw new ArgumentOutOfRangeException("usage");
            if (string.IsNullOrEmpty(subjectName))
                throw new ArgumentNullException("subjectName");

            CspParameters parameters = new CspParameters() {
                ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
                ProviderType = 24,
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = (int)KeyNumber.Signature,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            OidCollection oids = new OidCollection();

            switch (usage) {
                case CertificateUse.RootServer:
                    oids.Add(new Oid("1.3.6.1.4.1.45177.1.1", "LynxEmailSystemServerCommunications Root Server"));
                    break;
                case CertificateUse.BackupRootServer:
                    oids.Add(new Oid("1.3.6.1.4.1.45177.1.2", "LynxEmailSystemServerCommunications Backup Root Server"));
                    break;
                case CertificateUse.Server:
                    oids.Add(new Oid("1.3.6.1.4.1.45177.1.3", "LynxEmailSystemServerCommunications Server"));
                    break;
                case CertificateUse.Client:
                    oids.Add(new Oid("1.3.6.1.4.1.45177.2.1", "LynxEmailSystemServerCommunications Client"));
                    break;
                default:
                    break;
            }

            X509ExtensionCollection extensions = new X509ExtensionCollection();

            extensions.Add(new X509BasicConstraintsExtension(false, true, 1, false));
            extensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DataEncipherment |
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.KeyEncipherment |
                X509KeyUsageFlags.NonRepudiation, false));
            extensions.Add(new X509EnhancedKeyUsageExtension(oids, true));

            CertificateGenerationRequest cgr = new CertificateGenerationRequest() {
                Subject = subjectName,
                Parameters = parameters,
                SignatureAlgorithm = OID_RSA_SHA512RSA,
                ExpirationLength = TimeSpan.FromDays(365 * 5),
                KeySize = 4096,
                Extensions = extensions
            };

            X509Certificate2 cert = CertificateGenerator.CreateSelfSignedCertificate(cgr);
            return cert;

        }
    }
}
