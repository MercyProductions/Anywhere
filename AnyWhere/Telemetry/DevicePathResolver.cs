using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal sealed class DevicePathResolver
    {
        private readonly List<KeyValuePair<string, string>> _deviceMappings;

        public DevicePathResolver()
        {
            _deviceMappings = BuildDeviceMappings();
        }

        public string ToDosPath(string nativePath)
        {
            if (string.IsNullOrWhiteSpace(nativePath))
            {
                return nativePath;
            }

            foreach (KeyValuePair<string, string> pair in _deviceMappings)
            {
                if (nativePath.StartsWith(pair.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Value + nativePath.Substring(pair.Key.Length);
                }
            }

            return nativePath;
        }

        private static List<KeyValuePair<string, string>> BuildDeviceMappings()
        {
            List<KeyValuePair<string, string>> mappings = new List<KeyValuePair<string, string>>();

            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                try
                {
                    string driveName = drive.Name.TrimEnd('\\');
                    StringBuilder target = new StringBuilder(1024);
                    if (NativeMethods.QueryDosDevice(driveName, target, target.Capacity) == 0)
                    {
                        continue;
                    }

                    string devicePath = target.ToString();
                    int nullIndex = devicePath.IndexOf('\0');
                    if (nullIndex >= 0)
                    {
                        devicePath = devicePath.Substring(0, nullIndex);
                    }

                    if (!string.IsNullOrWhiteSpace(devicePath))
                    {
                        mappings.Add(new KeyValuePair<string, string>(devicePath, driveName));
                    }
                }
                catch
                {
                }
            }

            return mappings
                .OrderByDescending(pair => pair.Key.Length)
                .ToList();
        }
    }
}
