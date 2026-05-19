using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace AnyWhere.Telemetry
{
    internal static class AuthenticodeVerifier
    {
        private static readonly Guid WintrustActionGenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        public static SignatureVerificationResult VerifyFile(string path)
        {
            SignatureVerificationResult result = new SignatureVerificationResult
            {
                Status = "Unavailable",
                WinVerifyTrustStatus = -1
            };

            if (string.IsNullOrWhiteSpace(path) || !System.IO.File.Exists(path))
            {
                result.Status = "Missing";
                return result;
            }

            result.Subject = TryGetEmbeddedSignerSubject(path);
            int status = WinVerifyTrustFile(path);
            result.WinVerifyTrustStatus = status;

            if (status == 0)
            {
                result.Status = "Trusted";
            }
            else if (string.IsNullOrWhiteSpace(result.Subject))
            {
                result.Status = "UnsignedOrCatalogOnlyUntrusted";
            }
            else
            {
                result.Status = "UntrustedOrInvalid";
            }

            return result;
        }

        public static string TryGetEmbeddedSignerSubject(string path)
        {
            try
            {
                X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
                return certificate == null ? null : certificate.Subject;
            }
            catch
            {
                return null;
            }
        }

        private static int WinVerifyTrustFile(string fileName)
        {
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = fileName,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr fileInfoPtr = IntPtr.Zero;
            IntPtr dataPtr = IntPtr.Zero;

            try
            {
                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                WINTRUST_DATA data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2,
                    fdwRevocationChecks = 0,
                    dwUnionChoice = 1,
                    pFile = fileInfoPtr,
                    dwStateAction = 0,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = 0x00000010,
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };

                dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
                Marshal.StructureToPtr(data, dataPtr, false);

                Guid action = WintrustActionGenericVerifyV2;
                return WinVerifyTrust(IntPtr.Zero, ref action, dataPtr);
            }
            catch
            {
                return -1;
            }
            finally
            {
                if (dataPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(dataPtr);
                }

                if (fileInfoPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(fileInfoPtr);
                }
            }
        }

        [DllImport("wintrust.dll", PreserveSig = true, SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pcwszFilePath;

            public IntPtr hFile;

            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }
    }
}
