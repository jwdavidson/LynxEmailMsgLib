using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LynxEmailMsgLib.Crypto
{
    public static class CertificateSigner
    {
        public const int AT_KEYEXCHANGE = (int)Win32Native.AT_KEYEXCHANGE;
        public const int AT_SIGNATURE = (int)Win32Native.AT_SIGNATURE;

        /// <summary>
        /// Accepts a CSR-like object to sign by another key
        /// </summary>
        /// <param name="request">The request to sign</param>
        /// <param name="CACert">The signing key</param>
        /// <returns>Returns a signed certificate</returns>
        public static X509Certificate2 SignCertificate(CertificateSigningRequest request, X509Certificate2 CACert)
        {
            IntPtr hCAProv = IntPtr.Zero;

            IntPtr hProvAllocPtr = IntPtr.Zero;
            IntPtr subordinateCertInfoAllocPtr = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();

            try
            {
                // Get CA cert into CERT_CONTEXT
                // Get CA cert into CERT_INFO from context.pCertInfo

                Win32Native.CERT_CONTEXT CAContext = (Win32Native.CERT_CONTEXT)Marshal.PtrToStructure(CACert.Handle, typeof(Win32Native.CERT_CONTEXT));
                Win32Native.CERT_INFO CACertInfo = (Win32Native.CERT_INFO)Marshal.PtrToStructure(CAContext.pCertInfo, typeof(Win32Native.CERT_INFO));

                uint pcbData = 0;

                // get the context property handle of the CA Cert

                if (!Win32Native.CertGetCertificateContextProperty(CACert.Handle, 2, hProvAllocPtr, ref pcbData))
                    throw new CryptographicException(Marshal.GetLastWin32Error());

                hProvAllocPtr = Win32Native.LocalAlloc(0, new IntPtr((long)pcbData));

                if (!Win32Native.CertGetCertificateContextProperty(CACert.Handle, 2, hProvAllocPtr, ref pcbData))
                    throw new CryptographicException(Marshal.GetLastWin32Error());

                // get the key handle of the CA Cert

                Win32Native.CRYPT_KEY_PROV_INFO pKeyInfo = (Win32Native.CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(hProvAllocPtr, typeof(Win32Native.CRYPT_KEY_PROV_INFO));

                // Acquire a context to the provider for crypto

                if (!Win32Native.CryptAcquireContext(ref hCAProv, pKeyInfo.pwszContainerName, pKeyInfo.pwszProvName, pKeyInfo.dwProvType, pKeyInfo.dwFlags))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // Get subordinate cert into CERT_CONTEXT
                // Get subordinate cert into CERT_INFO from context.pCertInfo

                Win32Native.CERT_CONTEXT subordinateCertContext = (Win32Native.CERT_CONTEXT)Marshal.PtrToStructure(request.Certificate.Handle, typeof(Win32Native.CERT_CONTEXT));
                Win32Native.CERT_INFO subordinateCertInfo = (Win32Native.CERT_INFO)Marshal.PtrToStructure(subordinateCertContext.pCertInfo, typeof(Win32Native.CERT_INFO));

                Win32Native.CRYPT_ALGORITHM_IDENTIFIER signatureAlgo = new Win32Native.CRYPT_ALGORITHM_IDENTIFIER()
                {
                    pszObjId = string.IsNullOrWhiteSpace(request.SignatureAlgorithm) ? Win32Native.OID_RSA_SHA512RSA : request.SignatureAlgorithm
                };

                // apply new issuer

                subordinateCertInfo.NotBefore = CertUtil.FileTimeFromDateTime(DateTime.UtcNow.AddHours(-1));
                subordinateCertInfo.NotAfter = CertUtil.FileTimeFromDateTime(DateTime.UtcNow.Add(request.ExpirationLength));

                var caExtensions = CertUtil.ConvertExtensions(request.Extensions)[0];

                subordinateCertInfo.cExtension = request.Extensions == null ? 0 : (uint)request.Extensions.Count;
                subordinateCertInfo.rgExtension = caExtensions;

                subordinateCertInfo.SignatureAlgorithm = signatureAlgo;
                subordinateCertInfo.Issuer = CACertInfo.Subject;

                subordinateCertInfoAllocPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Win32Native.CERT_INFO)));
                Marshal.StructureToPtr(subordinateCertInfo, subordinateCertInfoAllocPtr, false);

                byte[] pbEncodedCert = null;
                uint pbEncodedCertLength = 0;

                if (!Win32Native.CryptSignAndEncodeCertificate(hCAProv,
                                                                 (uint)request.KeySpecification,
                                                                 Win32Native.X509_ASN_ENCODING,
                                                                 Win32Native.X509_CERT_TO_BE_SIGNED,
                                                                 subordinateCertInfoAllocPtr,
                                                                 ref signatureAlgo,
                                                                 IntPtr.Zero,
                                                                 pbEncodedCert,
                                                                 ref pbEncodedCertLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                pbEncodedCert = new byte[pbEncodedCertLength];

                if (!Win32Native.CryptSignAndEncodeCertificate(hCAProv,
                                                                 (uint)request.KeySpecification,
                                                                 Win32Native.X509_ASN_ENCODING,
                                                                 Win32Native.X509_CERT_TO_BE_SIGNED,
                                                                 subordinateCertInfoAllocPtr,
                                                                 ref signatureAlgo,
                                                                 IntPtr.Zero,
                                                                 pbEncodedCert,
                                                                 ref pbEncodedCertLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var cert3 = new X509Certificate2(pbEncodedCert);

                return cert3;
            }
            finally
            {
                if (hProvAllocPtr != IntPtr.Zero)
                    Win32Native.CryptReleaseContext(hProvAllocPtr, 0);

                if (hCAProv != IntPtr.Zero)
                    Win32Native.CryptReleaseContext(hCAProv, 0);

                if (hProvAllocPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(hProvAllocPtr);

                if (subordinateCertInfoAllocPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(subordinateCertInfoAllocPtr);
            }
        }
    }
}
