using System;
using System.Collections.Generic;
using System.Globalization;
using Microsoft.Win32;

namespace AnyWhere.Telemetry
{
    internal sealed class RegistrySnapshot
    {
        private RegistrySnapshot()
        {
            Keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public HashSet<string> Keys { get; private set; }

        public Dictionary<string, string> Values { get; private set; }

        public bool IsAvailable { get; private set; }

        public string Error { get; private set; }

        public static RegistrySnapshot Capture(RegistryWatchTarget target)
        {
            RegistrySnapshot snapshot = new RegistrySnapshot();

            try
            {
                using (RegistryKey baseKey = OpenBaseKey(target.Hive))
                using (RegistryKey key = baseKey.OpenSubKey(target.SubKeyPath, false))
                {
                    if (key == null)
                    {
                        snapshot.Error = "Key does not exist or is not accessible.";
                        return snapshot;
                    }

                    snapshot.IsAvailable = true;
                    CaptureKey(key, target.DisplayName, target.SnapshotDepth, snapshot);
                }
            }
            catch (Exception ex)
            {
                snapshot.Error = ex.Message;
            }

            return snapshot;
        }

        private static RegistryKey OpenBaseKey(RegistryHive hive)
        {
            try
            {
                return RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            }
            catch
            {
                return RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            }
        }

        private static void CaptureKey(RegistryKey key, string displayPath, int depthRemaining, RegistrySnapshot snapshot)
        {
            snapshot.Keys.Add(displayPath);

            string[] valueNames;
            try
            {
                valueNames = key.GetValueNames();
            }
            catch
            {
                valueNames = new string[0];
            }

            foreach (string valueName in valueNames)
            {
                try
                {
                    string normalizedValueName = string.IsNullOrEmpty(valueName) ? "(Default)" : valueName;
                    object value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    RegistryValueKind kind = key.GetValueKind(valueName);
                    snapshot.Values[displayPath + "\\" + normalizedValueName] = kind + ":" + ConvertValue(value);
                }
                catch (Exception ex)
                {
                    string normalizedValueName = string.IsNullOrEmpty(valueName) ? "(Default)" : valueName;
                    snapshot.Values[displayPath + "\\" + normalizedValueName] = "Error:" + ex.Message;
                }
            }

            if (depthRemaining <= 0)
            {
                return;
            }

            string[] subKeyNames;
            try
            {
                subKeyNames = key.GetSubKeyNames();
            }
            catch
            {
                return;
            }

            foreach (string subKeyName in subKeyNames)
            {
                try
                {
                    using (RegistryKey subKey = key.OpenSubKey(subKeyName, false))
                    {
                        if (subKey != null)
                        {
                            CaptureKey(subKey, displayPath + "\\" + subKeyName, depthRemaining - 1, snapshot);
                        }
                    }
                }
                catch
                {
                }
            }
        }

        private static string ConvertValue(object value)
        {
            if (value == null)
            {
                return "(null)";
            }

            byte[] bytes = value as byte[];
            if (bytes != null)
            {
                int take = Math.Min(bytes.Length, 128);
                string hex = BitConverter.ToString(bytes, 0, take);
                if (bytes.Length > take)
                {
                    hex += "...";
                }

                return hex;
            }

            string[] strings = value as string[];
            if (strings != null)
            {
                return string.Join("|", strings);
            }

            if (value is int || value is long || value is uint || value is ulong)
            {
                return Convert.ToString(value, CultureInfo.InvariantCulture);
            }

            return Convert.ToString(value, CultureInfo.InvariantCulture);
        }
    }
}
