using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class KernelModuleInventory
    {
        public static List<LoadedKernelModuleRecord> Capture(EventLogger logger)
        {
            List<LoadedKernelModuleRecord> modules = new List<LoadedKernelModuleRecord>();
            IntPtr[] imageBases = new IntPtr[4096];
            int needed;

            if (!NativeMethods.EnumDeviceDrivers(imageBases, imageBases.Length * IntPtr.Size, out needed))
            {
                logger.Log(DetectionEvent.Create(
                    "HiddenKernel",
                    "LoadedModuleEnumerationFailed",
                    EventSeverity.Medium,
                    "EnumDeviceDrivers failed. Kernel module visibility may be restricted.",
                    null,
                    null,
                    new Dictionary<string, string> { { "win32_error", Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture) } }));
                return modules;
            }

            int count = Math.Min(needed / IntPtr.Size, imageBases.Length);
            for (int i = 0; i < count; i++)
            {
                IntPtr imageBase = imageBases[i];
                if (imageBase == IntPtr.Zero)
                {
                    continue;
                }

                string path = QueryDriverPath(imageBase);
                string baseName = QueryDriverBaseName(imageBase);
                string normalized = KernelPathNormalizer.NormalizeDriverPath(path);

                modules.Add(new LoadedKernelModuleRecord
                {
                    BaseName = string.IsNullOrWhiteSpace(baseName) ? KernelPathNormalizer.NormalizeFileName(path) : baseName,
                    Path = path,
                    NormalizedPath = normalized,
                    NormalizedFileName = KernelPathNormalizer.NormalizeFileName(normalized ?? path),
                    ImageBase = unchecked((ulong)imageBase.ToInt64())
                });
            }

            return modules;
        }

        private static string QueryDriverPath(IntPtr imageBase)
        {
            StringBuilder builder = new StringBuilder(4096);
            int length = NativeMethods.GetDeviceDriverFileName(imageBase, builder, builder.Capacity);
            return length > 0 ? builder.ToString() : null;
        }

        private static string QueryDriverBaseName(IntPtr imageBase)
        {
            StringBuilder builder = new StringBuilder(1024);
            int length = NativeMethods.GetDeviceDriverBaseName(imageBase, builder, builder.Capacity);
            return length > 0 ? builder.ToString() : null;
        }
    }
}
