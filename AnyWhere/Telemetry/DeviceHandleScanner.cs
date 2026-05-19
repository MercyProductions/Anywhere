using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace AnyWhere.Telemetry
{
    internal static class DeviceHandleScanner
    {
        private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

        public static List<DeviceHandleRecord> ScanSuspiciousDeviceHandles(EventLogger logger, int maxHandlesToInspect)
        {
            List<DeviceHandleRecord> records = new List<DeviceHandleRecord>();
            IntPtr buffer = IntPtr.Zero;

            try
            {
                int length = 1024 * 1024;
                int returnedLength;
                int status;

                for (int attempt = 0; attempt < 6; attempt++)
                {
                    buffer = Marshal.AllocHGlobal(length);
                    status = NativeMethods.NtQuerySystemInformation(
                        NativeMethods.SystemExtendedHandleInformation,
                        buffer,
                        length,
                        out returnedLength);

                    if (status == 0)
                    {
                        break;
                    }

                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;

                    if (status != STATUS_INFO_LENGTH_MISMATCH)
                    {
                        return records;
                    }

                    length = Math.Max(length * 2, returnedLength + 1024);
                }

                if (buffer == IntPtr.Zero)
                {
                    return records;
                }

                long handleCount = Marshal.ReadIntPtr(buffer).ToInt64();
                IntPtr entryPtr = IntPtr.Add(buffer, IntPtr.Size * 2);
                int entrySize = Marshal.SizeOf(typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                int inspected = 0;

                for (long i = 0; i < handleCount && inspected < maxHandlesToInspect; i++)
                {
                    NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry =
                        (NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(
                            entryPtr,
                            typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

                    entryPtr = IntPtr.Add(entryPtr, entrySize);

                    int processId = unchecked((int)entry.UniqueProcessId.ToUInt64());
                    if (processId <= 4)
                    {
                        continue;
                    }

                    DeviceHandleRecord record = TryInspectHandle(processId, entry);
                    inspected++;

                    if (record != null && IsSuspiciousDeviceName(record.ObjectName))
                    {
                        records.Add(record);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogException("HiddenKernel", "DeviceHandleScanFailed", ex, null);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return records;
        }

        private static DeviceHandleRecord TryInspectHandle(int processId, NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry)
        {
            IntPtr processHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_DUP_HANDLE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (processHandle == IntPtr.Zero)
            {
                return null;
            }

            IntPtr duplicatedHandle = IntPtr.Zero;
            try
            {
                bool duplicated = NativeMethods.DuplicateHandle(
                    processHandle,
                    new IntPtr(unchecked((long)entry.HandleValue.ToUInt64())),
                    NativeMethods.GetCurrentProcess(),
                    out duplicatedHandle,
                    0,
                    false,
                    NativeMethods.DUPLICATE_SAME_ACCESS);

                if (!duplicated || duplicatedHandle == IntPtr.Zero)
                {
                    return null;
                }

                string objectType = QueryObjectString(duplicatedHandle, NativeMethods.ObjectTypeInformation);
                if (!string.Equals(objectType, "Device", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(objectType, "File", StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }

                string objectName = QueryObjectString(duplicatedHandle, NativeMethods.ObjectNameInformation);
                if (string.IsNullOrWhiteSpace(objectName))
                {
                    return null;
                }

                return new DeviceHandleRecord
                {
                    ProcessId = processId,
                    ProcessName = TryGetProcessName(processId),
                    ObjectType = objectType,
                    ObjectName = objectName,
                    GrantedAccess = entry.GrantedAccess,
                    HandleValue = entry.HandleValue.ToUInt64()
                };
            }
            catch
            {
                return null;
            }
            finally
            {
                if (duplicatedHandle != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(duplicatedHandle);
                }

                NativeMethods.CloseHandle(processHandle);
            }
        }

        private static string QueryObjectString(IntPtr handle, int informationClass)
        {
            int length = 4096;
            IntPtr buffer = IntPtr.Zero;

            try
            {
                int returnedLength;
                buffer = Marshal.AllocHGlobal(length);
                int status = NativeMethods.NtQueryObject(handle, informationClass, buffer, length, out returnedLength);
                if (status != 0)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;

                    if (returnedLength <= 0 || returnedLength > 1024 * 1024)
                    {
                        return null;
                    }

                    length = returnedLength;
                    buffer = Marshal.AllocHGlobal(length);
                    status = NativeMethods.NtQueryObject(handle, informationClass, buffer, length, out returnedLength);
                    if (status != 0)
                    {
                        return null;
                    }
                }

                NativeMethods.UNICODE_STRING unicodeString =
                    (NativeMethods.UNICODE_STRING)Marshal.PtrToStructure(buffer, typeof(NativeMethods.UNICODE_STRING));

                if (unicodeString.Length == 0 || unicodeString.Buffer == IntPtr.Zero)
                {
                    return null;
                }

                return Marshal.PtrToStringUni(unicodeString.Buffer, unicodeString.Length / 2);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private static bool IsSuspiciousDeviceName(string objectName)
        {
            if (string.IsNullOrWhiteSpace(objectName))
            {
                return false;
            }

            string lower = objectName.ToLowerInvariant();
            string[] suspiciousTerms =
            {
                "iqvw", "nal", "gdrv", "capcom", "dbutil", "rtcore", "winio", "eneio", "asrdrv",
                "mhyprot", "msio", "inpout", "physmem", "mapmem", "pmem", "kprocesshacker", "procexp"
            };

            foreach (string term in suspiciousTerms)
            {
                if (lower.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string TryGetProcessName(int processId)
        {
            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    return process.ProcessName;
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
