using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace AnyWhere.Telemetry
{
    internal sealed class RegistryKeyWatcher : IDisposable
    {
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly RegistryWatchTarget _target;
        private Thread _thread;
        private volatile bool _disposed;
        private IntPtr _nativeKey = IntPtr.Zero;
        private RegistrySnapshot _lastSnapshot;

        public RegistryKeyWatcher(EventLogger logger, MonitorOptions options, RegistryWatchTarget target)
        {
            _logger = logger;
            _options = options;
            _target = target;
        }

        public void Start()
        {
            _lastSnapshot = RegistrySnapshot.Capture(_target);
            if (!_lastSnapshot.IsAvailable)
            {
                _logger.Log(DetectionEvent.Create(
                    "Registry",
                    "WatchUnavailable",
                    EventSeverity.Low,
                    "Registry key is not available for monitoring: " + _target.DisplayName,
                    _target.DisplayName,
                    null,
                    new Dictionary<string, string> { { "error", _lastSnapshot.Error ?? "unknown" } }));
                return;
            }

            _thread = new Thread(ThreadMain)
            {
                IsBackground = true,
                Name = "Aegis Registry Watcher " + _target.DisplayName
            };
            _thread.Start();

            _logger.Log(DetectionEvent.Create(
                "Registry",
                "Baseline",
                EventSeverity.Low,
                "Registry watcher started: " + _target.DisplayName,
                _target.DisplayName,
                null,
                new Dictionary<string, string>
                {
                    { "key_count", _lastSnapshot.Keys.Count.ToString(CultureInfo.InvariantCulture) },
                    { "value_count", _lastSnapshot.Values.Count.ToString(CultureInfo.InvariantCulture) }
                }));
        }

        private void ThreadMain()
        {
            int openResult = NativeMethods.RegOpenKeyEx(
                GetHiveHandle(_target.Hive),
                _target.SubKeyPath,
                0,
                NativeMethods.KEY_NOTIFY | NativeMethods.KEY_READ,
                out _nativeKey);

            if (openResult != 0)
            {
                _logger.Log(DetectionEvent.Create(
                    "Registry",
                    "NativeWatchFailed",
                    EventSeverity.Medium,
                    "Could not open registry key for native notifications: " + _target.DisplayName,
                    _target.DisplayName,
                    null,
                    new Dictionary<string, string> { { "win32_error", openResult.ToString(CultureInfo.InvariantCulture) } }));
                return;
            }

            uint filter = NativeMethods.REG_NOTIFY_CHANGE_NAME |
                          NativeMethods.REG_NOTIFY_CHANGE_ATTRIBUTES |
                          NativeMethods.REG_NOTIFY_CHANGE_LAST_SET |
                          NativeMethods.REG_NOTIFY_CHANGE_SECURITY;

            while (!_disposed)
            {
                int result = NativeMethods.RegNotifyChangeKeyValue(_nativeKey, _target.WatchSubtree, filter, IntPtr.Zero, false);
                if (_disposed)
                {
                    break;
                }

                if (result == 0)
                {
                    RegistrySnapshot nextSnapshot = RegistrySnapshot.Capture(_target);
                    EmitDiff(_lastSnapshot, nextSnapshot);
                    _lastSnapshot = nextSnapshot;
                }
                else
                {
                    _logger.Log(DetectionEvent.Create(
                        "Registry",
                        "NotifyFailed",
                        EventSeverity.Medium,
                        "Registry notification failed for " + _target.DisplayName,
                        _target.DisplayName,
                        null,
                        new Dictionary<string, string> { { "win32_error", result.ToString(CultureInfo.InvariantCulture) } }));
                    Thread.Sleep(1000);
                }
            }
        }

        private void EmitDiff(RegistrySnapshot oldSnapshot, RegistrySnapshot newSnapshot)
        {
            if (newSnapshot == null || !newSnapshot.IsAvailable)
            {
                _logger.Log(DetectionEvent.Create(
                    "Registry",
                    "KeyUnavailable",
                    _target.Severity,
                    "Registry key became unavailable: " + _target.DisplayName,
                    _target.DisplayName,
                    null,
                    new Dictionary<string, string> { { "error", newSnapshot == null ? "unknown" : newSnapshot.Error ?? "unknown" } }));
                return;
            }

            int emitted = 0;
            foreach (string key in newSnapshot.Keys)
            {
                if (oldSnapshot == null || !oldSnapshot.Keys.Contains(key))
                {
                    if (!TryEmitRegistryEvent("KeyCreated", key, null, null, ref emitted))
                    {
                        return;
                    }
                }
            }

            if (oldSnapshot != null)
            {
                foreach (string key in oldSnapshot.Keys)
                {
                    if (!newSnapshot.Keys.Contains(key))
                    {
                        if (!TryEmitRegistryEvent("KeyDeleted", key, null, null, ref emitted))
                        {
                            return;
                        }
                    }
                }

                foreach (KeyValuePair<string, string> pair in newSnapshot.Values)
                {
                    string oldValue;
                    if (!oldSnapshot.Values.TryGetValue(pair.Key, out oldValue))
                    {
                        if (!TryEmitRegistryEvent("ValueCreated", pair.Key, null, pair.Value, ref emitted))
                        {
                            return;
                        }
                    }
                    else if (!string.Equals(oldValue, pair.Value, StringComparison.Ordinal))
                    {
                        if (!TryEmitRegistryEvent("ValueModified", pair.Key, oldValue, pair.Value, ref emitted))
                        {
                            return;
                        }
                    }
                }

                foreach (KeyValuePair<string, string> pair in oldSnapshot.Values)
                {
                    if (!newSnapshot.Values.ContainsKey(pair.Key))
                    {
                        if (!TryEmitRegistryEvent("ValueDeleted", pair.Key, pair.Value, null, ref emitted))
                        {
                            return;
                        }
                    }
                }
            }
        }

        private bool TryEmitRegistryEvent(string action, string path, string oldValue, string newValue, ref int emitted)
        {
            if (emitted >= _options.MaxRegistryDiffEventsPerBurst)
            {
                _logger.Log(DetectionEvent.Create(
                    "Registry",
                    "DiffTruncated",
                    EventSeverity.Medium,
                    "Registry change burst exceeded the event limit for " + _target.DisplayName,
                    _target.DisplayName,
                    null,
                    new Dictionary<string, string>
                    {
                        { "limit", _options.MaxRegistryDiffEventsPerBurst.ToString(CultureInfo.InvariantCulture) }
                    }));
                return false;
            }

            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "watch_target", _target.DisplayName }
            };

            if (oldValue != null)
            {
                details["old_value"] = TrimValue(oldValue);
            }

            if (newValue != null)
            {
                details["new_value"] = TrimValue(newValue);
            }

            _logger.Log(DetectionEvent.Create(
                "Registry",
                action,
                _target.Severity,
                "Registry " + action.ToLowerInvariant() + ": " + path,
                path,
                null,
                details));

            emitted++;
            return true;
        }

        private static string TrimValue(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= 1000)
            {
                return value;
            }

            return value.Substring(0, 1000) + "...";
        }

        private static IntPtr GetHiveHandle(RegistryHive hive)
        {
            switch (hive)
            {
                case RegistryHive.ClassesRoot:
                    return new IntPtr(unchecked((int)0x80000000));
                case RegistryHive.CurrentUser:
                    return new IntPtr(unchecked((int)0x80000001));
                case RegistryHive.LocalMachine:
                    return new IntPtr(unchecked((int)0x80000002));
                case RegistryHive.Users:
                    return new IntPtr(unchecked((int)0x80000003));
                case RegistryHive.CurrentConfig:
                    return new IntPtr(unchecked((int)0x80000005));
                default:
                    throw new ArgumentOutOfRangeException("hive");
            }
        }

        public void Dispose()
        {
            _disposed = true;
            IntPtr key = Interlocked.Exchange(ref _nativeKey, IntPtr.Zero);
            if (key != IntPtr.Zero)
            {
                NativeMethods.RegCloseKey(key);
            }
        }
    }
}
