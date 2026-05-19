using Microsoft.Win32;

namespace AnyWhere.Telemetry
{
    internal sealed class RegistryWatchTarget
    {
        public RegistryWatchTarget(RegistryHive hive, string subKeyPath, bool watchSubtree, int snapshotDepth, EventSeverity severity)
        {
            Hive = hive;
            SubKeyPath = subKeyPath;
            WatchSubtree = watchSubtree;
            SnapshotDepth = snapshotDepth;
            Severity = severity;
        }

        public RegistryHive Hive { get; private set; }

        public string SubKeyPath { get; private set; }

        public bool WatchSubtree { get; private set; }

        public int SnapshotDepth { get; private set; }

        public EventSeverity Severity { get; private set; }

        public string DisplayName
        {
            get { return HiveName(Hive) + "\\" + SubKeyPath; }
        }

        public static string HiveName(RegistryHive hive)
        {
            switch (hive)
            {
                case RegistryHive.ClassesRoot:
                    return "HKCR";
                case RegistryHive.CurrentUser:
                    return "HKCU";
                case RegistryHive.LocalMachine:
                    return "HKLM";
                case RegistryHive.Users:
                    return "HKU";
                case RegistryHive.CurrentConfig:
                    return "HKCC";
                default:
                    return hive.ToString();
            }
        }
    }
}
