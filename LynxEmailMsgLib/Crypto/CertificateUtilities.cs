using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
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
            Client,
            LocalCA 
        }

        const string OID_LYNX_ROOT_DIRECTORY = "1.3.6.1.4.1.45177.1.1";
        const string OID_LYNX_BACKUP_ROOT_DIRECTORY = "1.3.6.1.4.1.45177.1.2";
        const string OID_LYNX_DIRECTORY = "1.3.6.1.4.1.45177.1.3";
        const string OID_LYNX_CLIENT = "1.3.6.1.4.1.45177.2.1";
        const string OID_LYNX_ROOT_LOCAL_CA = "1.3.6.1.4.1.45177.3.1";

        public static X509Certificate2 BuildCertificate(CertificateUse usage, string subjectName)
        {
            if (!Enum.IsDefined(typeof(CertificateUse), usage))
                throw new ArgumentOutOfRangeException("usage");
            if (string.IsNullOrEmpty(subjectName))
                throw new ArgumentNullException("subjectName");

            SecureString passPhrase = new SecureString();

            return BuildCertificateInternal(usage, subjectName, passPhrase);
        }

        public static X509Certificate2 BuildCertificate(CertificateUse usage, string subjectName, SecureString passPhrase)
        {
            if (!Enum.IsDefined(typeof(CertificateUse), usage))
                throw new ArgumentOutOfRangeException("usage");
            if (string.IsNullOrEmpty(subjectName))
                throw new ArgumentNullException("subjectName");

            return BuildCertificateInternal(usage, subjectName, passPhrase);
        }

        private static X509Certificate2 BuildCertificateInternal(CertificateUse usage, string subjectName, SecureString passPhrase)
        {
            int keyNumber = 0;
            OidCollection oids = new OidCollection();
            CspProviderFlags cspFlags = new CspProviderFlags();
            cspFlags = CspProviderFlags.UseMachineKeyStore | CspProviderFlags.UseArchivableKey;
            TimeSpan expirationLength = TimeSpan.FromDays(365 * 5);

            X509KeyUsageFlags keyUseFlags = new X509KeyUsageFlags();
            keyUseFlags = X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.NonRepudiation;

            switch (usage) {
                case CertificateUse.RootServer:
                    oids.Add(new Oid(OID_LYNX_ROOT_DIRECTORY, "LynxEmailSystemServerCommunications Root Server"));
                    keyNumber = (int)KeyNumber.Exchange;
                    break;
                case CertificateUse.BackupRootServer:
                    oids.Add(new Oid(OID_LYNX_BACKUP_ROOT_DIRECTORY, "LynxEmailSystemServerCommunications Backup Root Server"));
                    keyNumber = (int)KeyNumber.Exchange;
                    break;
                case CertificateUse.Server:
                    oids.Add(new Oid(OID_LYNX_DIRECTORY, "LynxEmailSystemServerCommunications Server"));
                    keyNumber = (int)KeyNumber.Exchange;
                    break;
                case CertificateUse.Client:
                    oids.Add(new Oid(OID_LYNX_CLIENT, "LynxEmailSystemServerCommunications Client"));
                    keyNumber = (int)KeyNumber.Exchange;
                    cspFlags = CspProviderFlags.UseUserProtectedKey | CspProviderFlags.UseArchivableKey;
                    break;
                case CertificateUse.LocalCA:
                    oids.Add(new Oid(OID_LYNX_ROOT_LOCAL_CA, "LynxEmailSystemServerCommunications Local CA"));
                    keyNumber = (int)KeyNumber.Signature;
                    keyUseFlags = keyUseFlags | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign;
                    expirationLength = TimeSpan.FromDays(365 * 10);
                    break;
                default:
                    break;
            }
            CspParameters parameters = new CspParameters() {
                ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
                ProviderType = 24,
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = keyNumber,
                Flags = cspFlags
            };



            X509ExtensionCollection extensions = new X509ExtensionCollection();

            extensions.Add(new X509BasicConstraintsExtension(false, true, 1, false));
            extensions.Add(new X509KeyUsageExtension(keyUseFlags, false));
            extensions.Add(new X509EnhancedKeyUsageExtension(oids, true));

            CertificateGenerationRequest cgr = new CertificateGenerationRequest() {
                Subject = subjectName,
                Parameters = parameters,
                SignatureAlgorithm = Win32Native.OID_RSA_SHA512RSA,
                ExpirationLength = expirationLength,
                KeySize = 4096,
                Extensions = extensions
            };

            X509Certificate2 cert;

            if (passPhrase.Length > 0) {
                cert = CertificateGenerator.CreateSelfSignedCertificate(cgr, passPhrase);
            } else {
                cert = CertificateGenerator.CreateSelfSignedCertificate(cgr);
            }

            if (usage == CertificateUse.Client)
                cert = SignIt(cert);

            return cert;

        }

        private static X509Certificate2 SignIt(X509Certificate2 subordinate)
        {
            X509Certificate2Collection colCA = StoreUtilities.FindCertsByOID(StoreName.Root, StoreLocation.LocalMachine, OID_LYNX_ROOT_LOCAL_CA);
            if (colCA == null || colCA.Count <= 0)
                throw new Exception("Unable to locate Local Root CA.");

            X509Certificate2 CA = colCA[0];

            var csr = new CertificateSigningRequest() {
                KeySpecification = CertificateSigner.AT_SIGNATURE,
                Certificate = subordinate,
                ExpirationLength = subordinate.NotAfter - subordinate.NotBefore
            };

            return CertificateSigner.SignCertificate(csr, CA);
        }


    }
}
