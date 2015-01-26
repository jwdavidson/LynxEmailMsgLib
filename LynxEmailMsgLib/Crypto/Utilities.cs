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
    }
}
