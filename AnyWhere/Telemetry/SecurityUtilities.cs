using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AnyWhere.Telemetry
{
    internal static class SecurityUtilities
    {
        public static void TryEnableDebugPrivilege(EventLogger logger)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (!NativeMethods.OpenProcessToken(
                    Process.GetCurrentProcess().Handle,
                    NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY,
                    out tokenHandle))
                {
                    logger.Log(DetectionEvent.Create(
                        "Privilege",
                        "OpenTokenFailed",
                        EventSeverity.Medium,
                        "Could not open the process token for SeDebugPrivilege.",
                        null,
                        null,
                        LastErrorDetails()));
                    return;
                }

                NativeMethods.LUID luid;
                if (!NativeMethods.LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                {
                    logger.Log(DetectionEvent.Create(
                        "Privilege",
                        "LookupFailed",
                        EventSeverity.Medium,
                        "Could not look up SeDebugPrivilege.",
                        null,
                        null,
                        LastErrorDetails()));
                    return;
                }

                NativeMethods.TOKEN_PRIVILEGES privileges = new NativeMethods.TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = NativeMethods.SE_PRIVILEGE_ENABLED
                };

                bool adjusted = NativeMethods.AdjustTokenPrivileges(
                    tokenHandle,
                    false,
                    ref privileges,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero);

                int error = Marshal.GetLastWin32Error();
                if (!adjusted || error != 0)
                {
                    logger.Log(DetectionEvent.Create(
                        "Privilege",
                        "EnableFailed",
                        EventSeverity.Medium,
                        "SeDebugPrivilege could not be enabled. Some protected processes may be unavailable.",
                        null,
                        null,
                        new Dictionary<string, string> { { "win32_error", error.ToString() } }));
                    return;
                }

                logger.Log(DetectionEvent.Create(
                    "Privilege",
                    "Enabled",
                    EventSeverity.Low,
                    "SeDebugPrivilege enabled for deeper process and memory inspection.",
                    null,
                    null,
                    null));
            }
            catch (Exception ex)
            {
                logger.LogException("Privilege", "EnableException", ex, "SeDebugPrivilege");
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(tokenHandle);
                }
            }
        }

        private static Dictionary<string, string> LastErrorDetails()
        {
            return new Dictionary<string, string>
            {
                { "win32_error", Marshal.GetLastWin32Error().ToString() }
            };
        }
    }
}
