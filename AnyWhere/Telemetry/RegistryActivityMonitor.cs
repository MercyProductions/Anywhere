using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace AnyWhere.Telemetry
{
    internal sealed class RegistryActivityMonitor : IDetectionMonitor
    {
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly List<RegistryKeyWatcher> _watchers = new List<RegistryKeyWatcher>();

        public RegistryActivityMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
        }

        public string Name
        {
            get { return "Registry Activity"; }
        }

        public void Start()
        {
            foreach (RegistryWatchTarget target in BuildTargets())
            {
                RegistryKeyWatcher watcher = new RegistryKeyWatcher(_logger, _options, target);
                watcher.Start();
                _watchers.Add(watcher);
            }
        }

        private static IEnumerable<RegistryWatchTarget> BuildTargets()
        {
            yield return new RegistryWatchTarget(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved", true, 3, EventSeverity.Medium);
            yield return new RegistryWatchTarget(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies", true, 4, EventSeverity.Medium);
            yield return new RegistryWatchTarget(RegistryHive.CurrentUser, @"Software\Classes\ms-settings\Shell\Open\command", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.CurrentUser, @"Software\Classes\exefile\shell\open\command", true, 2, EventSeverity.High);

            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies", true, 4, EventSeverity.Medium);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI", true, 4, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard", true, 4, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", true, 4, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell", true, 4, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Sysmon", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SysmonDrv", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", true, 2, EventSeverity.Medium);

            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"HARDWARE\DESCRIPTION\System", true, 4, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"HARDWARE\DESCRIPTION\System\BIOS", true, 4, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\MountedDevices", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Enum", true, 2, EventSeverity.Medium);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Enum\DISPLAY", true, 3, EventSeverity.Medium);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Enum\STORAGE", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Enum\SCSI", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Enum\USBSTOR", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Class", true, 2, EventSeverity.Medium);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}", true, 4, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", true, 4, EventSeverity.Medium);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Cryptography", true, 4, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", true, 4, EventSeverity.Medium);
        }

        public void Dispose()
        {
            foreach (RegistryKeyWatcher watcher in _watchers)
            {
                try
                {
                    watcher.Dispose();
                }
                catch
                {
                }
            }

            _watchers.Clear();
        }
    }
}
