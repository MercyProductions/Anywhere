using System;
using System.Collections.Generic;
using System.Globalization;
using System.Management;

namespace AnyWhere.Telemetry
{
    internal static class DriverServiceInventory
    {
        public static List<DriverServiceRecord> Capture(EventLogger logger)
        {
            List<DriverServiceRecord> services = new List<DriverServiceRecord>();

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT Name, DisplayName, State, StartMode, ServiceType, PathName FROM Win32_SystemDriver"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        using (obj)
                        {
                            string pathName = Convert.ToString(obj["PathName"], CultureInfo.InvariantCulture);
                            string normalized = KernelPathNormalizer.NormalizeDriverPath(pathName);

                            services.Add(new DriverServiceRecord
                            {
                                Name = Convert.ToString(obj["Name"], CultureInfo.InvariantCulture),
                                DisplayName = Convert.ToString(obj["DisplayName"], CultureInfo.InvariantCulture),
                                State = Convert.ToString(obj["State"], CultureInfo.InvariantCulture),
                                StartMode = Convert.ToString(obj["StartMode"], CultureInfo.InvariantCulture),
                                ServiceType = Convert.ToString(obj["ServiceType"], CultureInfo.InvariantCulture),
                                PathName = pathName,
                                NormalizedPath = normalized,
                                NormalizedFileName = KernelPathNormalizer.NormalizeFileName(normalized ?? pathName)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogException("HiddenKernel", "DriverServiceEnumerationFailed", ex, null);
            }

            return services;
        }
    }
}
