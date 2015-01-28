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
    public class StoreUtilities
    {
        public enum SupportedFindTypes
        {
            ByName,
            ByThumbprint
        }
        public static bool StoreCert(StoreName name, StoreLocation loc, X509Certificate2 cert)
        {
            if (!Enum.IsDefined(typeof(StoreName), name))
                throw new ArgumentOutOfRangeException("name");
            if (!Enum.IsDefined(typeof(StoreLocation), loc))
                throw new ArgumentOutOfRangeException("loc");
            if (cert == null || cert.Thumbprint.Length <= 0)
                throw new ArgumentNullException("cert");

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

        public static X509Certificate2 FindCertBy(StoreName name, StoreLocation loc, SupportedFindTypes findType, string findItem)
        {
            if (!Enum.IsDefined(typeof(StoreName), name))
                throw new ArgumentOutOfRangeException("name");
            if (!Enum.IsDefined(typeof(StoreLocation), loc))
                throw new ArgumentOutOfRangeException("loc");
            if (!Enum.IsDefined(typeof(SupportedFindTypes), findType))
                throw new ArgumentOutOfRangeException("findType");
            if (string.IsNullOrEmpty(findItem))
                throw new ArgumentNullException("findItem");

            X509Store store = new X509Store(name, loc);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            try {
                X509Certificate2Collection certCol = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection findCol;

                switch (findType) {
                    case SupportedFindTypes.ByName:
                        findCol = (X509Certificate2Collection)certCol.Find(X509FindType.FindBySubjectName, findItem, true);
                        break;
                    case SupportedFindTypes.ByThumbprint:
                        findCol = (X509Certificate2Collection)certCol.Find(X509FindType.FindByThumbprint, findItem, true);
                        break;
                    default:
                        findCol = null;
                        break;
                }

                if (findCol != null && findCol.Count > 0) {
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
            if (!Enum.IsDefined(typeof(StoreName), name))
                throw new ArgumentOutOfRangeException("name");
            if (!Enum.IsDefined(typeof(StoreLocation), loc))
                throw new ArgumentOutOfRangeException("loc");
            if (string.IsNullOrEmpty(oid))
                throw new ArgumentNullException("oid");

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
