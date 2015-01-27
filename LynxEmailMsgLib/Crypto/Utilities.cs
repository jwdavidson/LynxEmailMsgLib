using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LynxEmailMsgLib.Crypto
{
    public class Utilities
    {
        public static bool StoreCert(StoreName name, StoreLocation loc, X509Certificate2 cert)
        {
            X509Store store = new X509Store(name, loc);
            store.Open(OpenFlags.ReadWrite);

            try {
                store.Add(cert);
                return true;
            }
            catch {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally {
                store.Close();
            }
        }

        public static X509Certificate2 FindCertByName(StoreName name, StoreLocation loc, string certName)
        {
            X509Store store = new X509Store(name, loc);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            try {
                X509Certificate2Collection certCol = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection findCol = (X509Certificate2Collection)certCol.Find(X509FindType.FindBySubjectName, certName, true);
                if (findCol.Count > 0) {
                    return findCol[0];
                } else return null;
            }
            catch {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally {
                store.Close();
            }
        }

        public static X509Certificate2Collection FindCertsByOID(StoreName name, StoreLocation loc, string oid)
        {
            X509Store store = new X509Store(name, loc);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            try {
                X509Certificate2Collection certCol = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection findCol = (X509Certificate2Collection)certCol.Find(X509FindType.FindByExtension, "2.5.29.37", false);
                if (findCol.Count > 0) {
                    X509Certificate2Collection foundCol = new X509Certificate2Collection();
                    foreach (X509Certificate2 testCert in findCol){
                        List<X509EnhancedKeyUsageExtension> keyExtensions = testCert.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToList();
                        foreach (X509EnhancedKeyUsageExtension keyExtension in keyExtensions) {
                            foreach (Oid testOid in keyExtension.EnhancedKeyUsages) {
                                if (testOid.Value == oid) {
                                    foundCol.Add(testCert);
                                }
                            }
                        }
                    }
                    return foundCol;
                } else return null;
            }
            catch {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally {
                store.Close();
            }
        }
    }
}
