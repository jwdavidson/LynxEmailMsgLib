﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LynxEmailMsgLib.Crypto
{
    internal static class CertUtil
    {
        internal unsafe static List<IntPtr> ConvertExtensions(X509ExtensionCollection extensions)
        {
            List<IntPtr> ret = new List<IntPtr>();

            if (extensions == null || extensions.Count == 0)
            {
                ret.Add(IntPtr.Zero);
                return ret;
            }

            int extensionStructSize = Marshal.SizeOf(typeof(Win32Native.CERT_EXTENSION));
            Win32Native.CERT_EXTENSIONS extensionsStruct = new Win32Native.CERT_EXTENSIONS();

            IntPtr extensionsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Win32Native.CERT_EXTENSIONS)));

            ret.Add(extensionsPtr);

            extensionsStruct.cExtension = (uint)extensions.Count;
            extensionsStruct.rgExtension = Marshal.AllocHGlobal(extensionStructSize * extensions.Count);

            ret.Add(extensionsStruct.rgExtension);

            Marshal.StructureToPtr(extensionsStruct, extensionsPtr, false);
            Win32Native.CERT_EXTENSION extensionStruct = new Win32Native.CERT_EXTENSION();

            byte* workPointer = (byte*)extensionsStruct.rgExtension.ToPointer();

            foreach (X509Extension ext in extensions)
            {
                extensionStruct.pszObjId = Marshal.StringToHGlobalAnsi(ext.Oid.Value);
                ret.Add(extensionStruct.pszObjId);

                extensionStruct.fCritical = ext.Critical;
                byte[] rawData = ext.RawData;

                extensionStruct.Value = new Win32Native.CRYPTOAPI_BLOB();

                extensionStruct.Value.cbData = (uint)rawData.Length;
                extensionStruct.Value.pbData = Marshal.AllocHGlobal(rawData.Length); ;

                Marshal.Copy(rawData, 0, extensionStruct.Value.pbData, rawData.Length);

                ret.Add(extensionStruct.Value.pbData);

                Marshal.StructureToPtr(extensionStruct, new IntPtr(workPointer), false);
                workPointer += extensionStructSize;
            }

            return ret;
        }

        internal static Dictionary<string, int> ReadAllProviders()
        {
            var installedCSPs = new Dictionary<string, int>();
            StringBuilder pszName;

            int cbName;
            int dwType;
            int dwIndex;

            dwIndex = 0;
            dwType = 1;
            cbName = 0;

            while (Win32Native.CryptEnumProviders(dwIndex, IntPtr.Zero, 0, ref dwType, null, ref cbName))
            {
                pszName = new StringBuilder(cbName);

                if (Win32Native.CryptEnumProviders(dwIndex++, IntPtr.Zero, 0, ref dwType, pszName, ref cbName))
                {
                    installedCSPs.Add(pszName.ToString(), dwType);
                }
            }

            return installedCSPs;
        }

        internal static System.Runtime.InteropServices.ComTypes.FILETIME FileTimeFromDateTime(DateTime date)
        {
            long ftime = date.ToFileTime();

            System.Runtime.InteropServices.ComTypes.FILETIME ft = new System.Runtime.InteropServices.ComTypes.FILETIME();

            ft.dwHighDateTime = (int)(ftime >> 32);
            ft.dwLowDateTime = (int)ftime;

            return ft;
        }
    }
}
