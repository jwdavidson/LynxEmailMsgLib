//
// This code was written by Keith Brown, and may be freely used.
// Want to learn more about .NET? Visit pluralsight.com today!
//
using System;
using LynxEmailMsgLib.Crypto.UI;
using System.Windows.Forms;
using LynxEmailMsgLib.Crypto;
using System.Security.Cryptography.X509Certificates;

namespace LynxEmailMsgClient
{
    public static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

            new GenerateSelfSignedCertForm().ShowDialog();
        }

        static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            MessageBox.Show(((Exception)e.ExceptionObject).ToString());
        }

        // note you'll need a reference to System.Security.dll to get support for X509Certificate2UI.
        public static void GenSelfSignedCert()
        {
            using (CryptContext ctx = new CryptContext()) {
                ctx.Open();

                X509Certificate2 cert = ctx.CreateSelfSignedCertificate(
                    new SelfSignedCertProperties {
                        IsPrivateKeyExportable = true,
                        KeyBitLength = 4096,
                        Name = new X500DistinguishedName("cn=localhost"),
                        ValidFrom = DateTime.Today.AddDays(-1),
                        ValidTo = DateTime.Today.AddYears(1),
                    });

                X509Certificate2UI.DisplayCertificate(cert);
            }
        }

        public static void GenAndStoreSelfSignedCertByForm(string sDN)
        {
            // A self-signed cert needs to be placed in the Root to be usable
            // To save to the LocalMachine it must be an Administrator or Service Account
            // A user can only store to Current User
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            BackgroundCertGenForm form = new BackgroundCertGenForm();
            form.CertProperties = new SelfSignedCertProperties {
                Name = new X500DistinguishedName("CN=" + sDN),
                ValidFrom = DateTime.UtcNow.AddDays(-1),
                ValidTo = DateTime.UtcNow.AddYears(1),
                KeyBitLength = 4096,
                IsPrivateKeyExportable = true
            };
            form.ShowDialog();

            X509Certificate2 cert = form.Certificate;
          
            if (cert != null) {
                byte[] pfx = cert.Export(X509ContentType.Pfx);
                cert = new X509Certificate2(pfx, (string)null, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

                store.Add(cert);
            }
            store.Close();

            if (cert != null) {
                new CertDetailsForm {
                    Certificate = cert,
                    CertStoreLocation = StoreLocation.LocalMachine,
                    CertStoreName = StoreName.Root
                }.ShowDialog();
            }
        }

    }
}
