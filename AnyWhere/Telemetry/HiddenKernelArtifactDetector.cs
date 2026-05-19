using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class HiddenKernelArtifactDetector : IDetectionMonitor
    {
        private static readonly TimeSpan ShortLivedDriverWindow = TimeSpan.FromMinutes(5);
        private static readonly string[] SuspiciousLoaderTerms =
        {
            "kdmapper", "drvmap", "iqvw64e", "naldrv", "gdrv", "capcom", "dbutil", "rtcore64",
            "winio64", "eneio64", "asrdrv", "mhyprot", "msio64", "inpoutx64", "physmem",
            "sc.exe create", "type= kernel", "fltmc load", "pnputil /add-driver"
        };

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private readonly ConcurrentDictionary<string, DriverDropRecord> _driverDrops = new ConcurrentDictionary<string, DriverDropRecord>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedProcessKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedMismatchKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedHandleKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private Thread _thread;
        private bool _initialScan = true;

        public HiddenKernelArtifactDetector(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
        }

        public string Name
        {
            get { return "Hidden Kernel Artifacts"; }
        }

        public void Start()
        {
            foreach (string root in BuildDriverWatchRoots())
            {
                TryAddWatcher(root);
            }

            _thread = new Thread(ThreadMain)
            {
                IsBackground = true,
                Name = "Aegis Hidden Kernel Artifact Detector"
            };
            _thread.Start();

            _logger.Log(DetectionEvent.Create(
                "HiddenKernel",
                "Started",
                EventSeverity.Low,
                "Hidden kernel artifact detector started in evidence-only mode.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "driver_watch_roots", string.Join(";", BuildDriverWatchRoots().ToArray()) },
                    { "kernel_scan_interval_seconds", _options.KernelArtifactScanInterval.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "read_only", "True" }
                }));
        }

        private void ThreadMain()
        {
            while (!_stopSignal.IsSet)
            {
                try
                {
                    ScanOnce();
                }
                catch (Exception ex)
                {
                    _logger.LogException("HiddenKernel", "ScanFailed", ex, null);
                }

                _stopSignal.Wait(_options.KernelArtifactScanInterval);
            }
        }

        private void ScanOnce()
        {
            List<LoadedKernelModuleRecord> modules = KernelModuleInventory.Capture(_logger);
            List<DriverServiceRecord> services = DriverServiceInventory.Capture(_logger);
            List<DriverFileRecord> driverFiles = ScanKnownDriverFiles();

            CompareServicesAndModules(services, modules);
            CompareDriverFilesAndModules(driverFiles, modules, services);
            DetectSuspiciousLoaderProcesses();
            DetectSuspiciousDeviceHandles();
            ReportKernelAssistState(modules);

            if (_initialScan)
            {
                _logger.Log(DetectionEvent.Create(
                    "HiddenKernel",
                    "Baseline",
                    EventSeverity.Low,
                    "Hidden-kernel artifact baseline complete.",
                    null,
                    null,
                    new Dictionary<string, string>
                    {
                        { "loaded_module_count", modules.Count.ToString(CultureInfo.InvariantCulture) },
                        { "driver_service_count", services.Count.ToString(CultureInfo.InvariantCulture) },
                        { "known_driver_file_count", driverFiles.Count.ToString(CultureInfo.InvariantCulture) }
                    }));

                _initialScan = false;
            }
        }

        private void CompareServicesAndModules(ICollection<DriverServiceRecord> services, ICollection<LoadedKernelModuleRecord> modules)
        {
            HashSet<string> loadedByPath = new HashSet<string>(modules.Select(m => m.NormalizedPath).Where(p => !string.IsNullOrWhiteSpace(p)), StringComparer.OrdinalIgnoreCase);
            HashSet<string> loadedByName = new HashSet<string>(modules.Select(m => m.NormalizedFileName).Where(p => !string.IsNullOrWhiteSpace(p)), StringComparer.OrdinalIgnoreCase);
            HashSet<string> serviceByPath = new HashSet<string>(services.Select(s => s.NormalizedPath).Where(p => !string.IsNullOrWhiteSpace(p)), StringComparer.OrdinalIgnoreCase);
            HashSet<string> serviceByName = new HashSet<string>(services.Select(s => s.NormalizedFileName).Where(p => !string.IsNullOrWhiteSpace(p)), StringComparer.OrdinalIgnoreCase);

            foreach (DriverServiceRecord service in services)
            {
                if (!service.IsRunning || string.IsNullOrWhiteSpace(service.NormalizedFileName))
                {
                    continue;
                }

                bool loaded = loadedByPath.Contains(service.NormalizedPath) || loadedByName.Contains(service.NormalizedFileName);
                if (!loaded)
                {
                    EmitOnce(
                        "ServiceRunningModuleMissing|" + service.Name + "|" + service.NormalizedFileName,
                        "ServiceRunningModuleMissing",
                        EventSeverity.High,
                        "Running kernel driver service has no matching loaded module inventory entry: " + service.Name,
                        service.NormalizedPath,
                        ServiceDetails(service));
                }
            }

            foreach (LoadedKernelModuleRecord module in modules)
            {
                if (string.IsNullOrWhiteSpace(module.NormalizedFileName))
                {
                    continue;
                }

                bool hasService = serviceByPath.Contains(module.NormalizedPath) || serviceByName.Contains(module.NormalizedFileName);
                if (!hasService && !IsWindowsCoreModule(module.NormalizedPath))
                {
                    Dictionary<string, string> details = ModuleDetails(module);
                    AddSignatureDetails(module.NormalizedPath, details);
                    EmitOnce(
                        "LoadedModuleNoService|" + module.NormalizedFileName + "|" + module.ImageBase.ToString("X", CultureInfo.InvariantCulture),
                        "LoadedModuleNoService",
                        EventSeverity.Medium,
                        "Loaded kernel module has no matching SCM driver service: " + module.NormalizedFileName,
                        module.NormalizedPath,
                        details);
                }
            }
        }

        private void CompareDriverFilesAndModules(ICollection<DriverFileRecord> files, ICollection<LoadedKernelModuleRecord> modules, ICollection<DriverServiceRecord> services)
        {
            HashSet<string> loadedByName = new HashSet<string>(modules.Select(m => m.NormalizedFileName).Where(p => !string.IsNullOrWhiteSpace(p)), StringComparer.OrdinalIgnoreCase);
            HashSet<string> serviceByName = new HashSet<string>(services.Select(s => s.NormalizedFileName).Where(p => !string.IsNullOrWhiteSpace(p)), StringComparer.OrdinalIgnoreCase);
            DateTime cutoff = DateTime.UtcNow.Subtract(TimeSpan.FromHours(24));

            foreach (DriverFileRecord file in files)
            {
                bool loaded = loadedByName.Contains(file.NormalizedFileName);
                bool hasService = serviceByName.Contains(file.NormalizedFileName);
                bool recent = file.CreatedUtc >= cutoff || file.ModifiedUtc >= cutoff;
                bool untrusted = !string.Equals(file.SignatureStatus, "Trusted", StringComparison.OrdinalIgnoreCase);

                if (recent && untrusted)
                {
                    Dictionary<string, string> details = DriverFileDetails(file);
                    details["loaded"] = loaded.ToString();
                    details["has_scm_service"] = hasService.ToString();

                    EmitOnce(
                        "RecentUntrustedDriverFile|" + file.Path,
                        "RecentUntrustedDriverFile",
                        EventSeverity.High,
                        "Recently dropped driver file is not trusted: " + Path.GetFileName(file.Path),
                        file.Path,
                        details);
                }
            }
        }

        private void DetectSuspiciousLoaderProcesses()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject process in results)
                    {
                        using (process)
                        {
                            string name = Convert.ToString(process["Name"], CultureInfo.InvariantCulture);
                            string path = Convert.ToString(process["ExecutablePath"], CultureInfo.InvariantCulture);
                            string commandLine = Convert.ToString(process["CommandLine"], CultureInfo.InvariantCulture);
                            string haystack = (name + " " + path + " " + commandLine).ToLowerInvariant();
                            string matchedTerm = null;

                            foreach (string term in SuspiciousLoaderTerms)
                            {
                                if (haystack.IndexOf(term.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    matchedTerm = term;
                                    break;
                                }
                            }

                            if (matchedTerm == null)
                            {
                                continue;
                            }

                            int processId = Convert.ToInt32(process["ProcessId"], CultureInfo.InvariantCulture);
                            string key = processId.ToString(CultureInfo.InvariantCulture) + "|" + matchedTerm;
                            lock (_reportedProcessKeys)
                            {
                                if (!_reportedProcessKeys.Add(key))
                                {
                                    continue;
                                }
                            }

                            Dictionary<string, string> details = new Dictionary<string, string>
                            {
                                { "matched_indicator", matchedTerm },
                                { "process_name", name ?? string.Empty },
                                { "executable_path", path ?? string.Empty },
                                { "command_line", commandLine ?? string.Empty }
                            };

                            _logger.Log(DetectionEvent.CreateForProcess(
                                "HiddenKernel",
                                "SuspiciousDriverLoaderProcess",
                                EventSeverity.High,
                                "Process matches suspicious vulnerable-driver-loader indicators: " + name,
                                path,
                                processId,
                                name,
                                details));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException("HiddenKernel", "ProcessIndicatorScanFailed", ex, null);
            }
        }

        private void DetectSuspiciousDeviceHandles()
        {
            if (_options.MaxDeviceHandlesToInspect <= 0)
            {
                return;
            }

            foreach (DeviceHandleRecord record in DeviceHandleScanner.ScanSuspiciousDeviceHandles(_logger, _options.MaxDeviceHandlesToInspect))
            {
                string key = record.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + record.ObjectName + "|" + record.GrantedAccess.ToString("X", CultureInfo.InvariantCulture);
                lock (_reportedHandleKeys)
                {
                    if (!_reportedHandleKeys.Add(key))
                    {
                        continue;
                    }
                }

                _logger.Log(DetectionEvent.CreateForProcess(
                    "HiddenKernel",
                    "SuspiciousDeviceHandle",
                    EventSeverity.High,
                    "Process has a visible handle to a suspicious device object: " + record.ObjectName,
                    record.ObjectName,
                    record.ProcessId,
                    record.ProcessName,
                    new Dictionary<string, string>
                    {
                        { "object_type", record.ObjectType ?? string.Empty },
                        { "object_name", record.ObjectName ?? string.Empty },
                        { "granted_access", "0x" + record.GrantedAccess.ToString("X", CultureInfo.InvariantCulture) },
                        { "handle_value", "0x" + record.HandleValue.ToString("X", CultureInfo.InvariantCulture) },
                        { "visibility_limit", "User-mode handle enumeration only; kernel-hidden objects may not be visible." }
                    }));
            }
        }

        private void ReportKernelAssistState(ICollection<LoadedKernelModuleRecord> modules)
        {
            if (!_initialScan)
            {
                return;
            }

            _logger.Log(DetectionEvent.Create(
                "HiddenKernel",
                "KernelAssistUnavailable",
                EventSeverity.Medium,
                "No signed/test-signed Aegis defensive kernel sensor is connected; deep hidden-kernel checks are not active.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "expected_device", "\\\\.\\AegisKernelSensor" },
                    { "active_mode", "user-mode evidence collection" },
                    { "loaded_module_inventory_count", modules.Count.ToString(CultureInfo.InvariantCulture) },
                    { "read_only_rule", "Detector logs evidence only and does not patch, unload, or interfere." }
                }));
        }

        private List<DriverFileRecord> ScanKnownDriverFiles()
        {
            List<DriverFileRecord> files = new List<DriverFileRecord>();
            foreach (string root in BuildDriverScanRoots())
            {
                try
                {
                    if (!Directory.Exists(root))
                    {
                        continue;
                    }

                    foreach (string path in Directory.EnumerateFiles(root, "*.sys", SearchOption.TopDirectoryOnly))
                    {
                        DriverFileRecord record = BuildDriverFileRecord(path, includeHash: false);
                        if (record != null)
                        {
                            files.Add(record);
                        }
                    }
                }
                catch
                {
                }
            }

            return files;
        }

        private DriverFileRecord BuildDriverFileRecord(string path, bool includeHash)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return null;
                }

                FileInfo info = new FileInfo(path);
                SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(path);

                return new DriverFileRecord
                {
                    Path = path,
                    NormalizedFileName = KernelPathNormalizer.NormalizeFileName(path),
                    SizeBytes = info.Length,
                    CreatedUtc = info.CreationTimeUtc,
                    ModifiedUtc = info.LastWriteTimeUtc,
                    SignatureStatus = signature.Status,
                    SignatureSubject = signature.Subject,
                    Sha256 = includeHash && info.Length <= _options.MaxHashBytes ? TrySha256(path) : null
                };
            }
            catch
            {
                return null;
            }
        }

        private void TryAddWatcher(string root)
        {
            try
            {
                if (!Directory.Exists(root))
                {
                    return;
                }

                FileSystemWatcher watcher = new FileSystemWatcher(root, "*.sys")
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 64 * 1024,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.Security
                };

                watcher.Created += OnDriverCreated;
                watcher.Deleted += OnDriverDeleted;
                watcher.Renamed += OnDriverRenamed;
                watcher.Changed += OnDriverChanged;
                watcher.Error += OnWatcherError;
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogException("HiddenKernel", "DriverFileWatcherFailed", ex, root);
            }
        }

        private void OnDriverCreated(object sender, FileSystemEventArgs eventArgs)
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                Thread.Sleep(300);
                DriverFileRecord record = BuildDriverFileRecord(eventArgs.FullPath, includeHash: true);
                DriverDropRecord drop = new DriverDropRecord
                {
                    Path = eventArgs.FullPath,
                    CreatedUtc = DateTime.UtcNow,
                    FileRecord = record
                };
                _driverDrops[eventArgs.FullPath] = drop;

                Dictionary<string, string> details = record == null
                    ? new Dictionary<string, string>()
                    : DriverFileDetails(record);

                _logger.Log(DetectionEvent.Create(
                    "HiddenKernel",
                    IsUntrusted(record) ? "UntrustedDriverDropped" : "DriverFileCreated",
                    IsUntrusted(record) ? EventSeverity.High : EventSeverity.Medium,
                    "Driver file created: " + eventArgs.FullPath,
                    eventArgs.FullPath,
                    null,
                    details));
            });
        }

        private void OnDriverDeleted(object sender, FileSystemEventArgs eventArgs)
        {
            DriverDropRecord drop;
            bool shortLived = _driverDrops.TryRemove(eventArgs.FullPath, out drop) &&
                              DateTime.UtcNow.Subtract(drop.CreatedUtc) <= ShortLivedDriverWindow;

            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "short_lived", shortLived.ToString() },
                { "short_lived_window_seconds", ShortLivedDriverWindow.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) }
            };

            if (drop != null && drop.FileRecord != null)
            {
                foreach (KeyValuePair<string, string> pair in DriverFileDetails(drop.FileRecord))
                {
                    details[pair.Key] = pair.Value;
                }
            }

            _logger.Log(DetectionEvent.Create(
                "HiddenKernel",
                shortLived ? "ShortLivedDriverFileDeleted" : "DriverFileDeleted",
                shortLived ? EventSeverity.High : EventSeverity.Medium,
                "Driver file deleted: " + eventArgs.FullPath,
                eventArgs.FullPath,
                null,
                details));
        }

        private void OnDriverRenamed(object sender, RenamedEventArgs eventArgs)
        {
            _logger.Log(DetectionEvent.Create(
                "HiddenKernel",
                "DriverFileRenamed",
                EventSeverity.High,
                "Driver file renamed from " + eventArgs.OldFullPath + " to " + eventArgs.FullPath,
                eventArgs.FullPath,
                null,
                new Dictionary<string, string> { { "old_path", eventArgs.OldFullPath } }));
        }

        private void OnDriverChanged(object sender, FileSystemEventArgs eventArgs)
        {
            if (!_driverDrops.ContainsKey(eventArgs.FullPath))
            {
                return;
            }

            _logger.Log(DetectionEvent.Create(
                "HiddenKernel",
                "RecentlyDroppedDriverChanged",
                EventSeverity.Medium,
                "Recently dropped driver file changed: " + eventArgs.FullPath,
                eventArgs.FullPath,
                null,
                null));
        }

        private void OnWatcherError(object sender, ErrorEventArgs eventArgs)
        {
            _logger.Log(DetectionEvent.Create(
                "HiddenKernel",
                "DriverFileWatcherError",
                EventSeverity.Medium,
                "Driver file watcher reported an error.",
                null,
                null,
                new Dictionary<string, string> { { "exception", eventArgs.GetException().Message } }));
        }

        private void EmitOnce(string key, string action, EventSeverity severity, string description, string path, Dictionary<string, string> details)
        {
            lock (_reportedMismatchKeys)
            {
                if (!_reportedMismatchKeys.Add(key))
                {
                    return;
                }
            }

            _logger.Log(DetectionEvent.Create(
                "HiddenKernel",
                action,
                severity,
                description,
                path,
                null,
                details));
        }

        private static Dictionary<string, string> ServiceDetails(DriverServiceRecord service)
        {
            return new Dictionary<string, string>
            {
                { "service_name", service.Name ?? string.Empty },
                { "display_name", service.DisplayName ?? string.Empty },
                { "state", service.State ?? string.Empty },
                { "start_mode", service.StartMode ?? string.Empty },
                { "service_type", service.ServiceType ?? string.Empty },
                { "path_name", service.PathName ?? string.Empty },
                { "normalized_path", service.NormalizedPath ?? string.Empty }
            };
        }

        private static Dictionary<string, string> ModuleDetails(LoadedKernelModuleRecord module)
        {
            return new Dictionary<string, string>
            {
                { "module_base_name", module.BaseName ?? string.Empty },
                { "module_path", module.Path ?? string.Empty },
                { "normalized_path", module.NormalizedPath ?? string.Empty },
                { "image_base", "0x" + module.ImageBase.ToString("X", CultureInfo.InvariantCulture) }
            };
        }

        private static Dictionary<string, string> DriverFileDetails(DriverFileRecord file)
        {
            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "driver_path", file.Path ?? string.Empty },
                { "driver_file_name", file.NormalizedFileName ?? string.Empty },
                { "size_bytes", file.SizeBytes.ToString(CultureInfo.InvariantCulture) },
                { "created_utc", file.CreatedUtc.ToString("o", CultureInfo.InvariantCulture) },
                { "modified_utc", file.ModifiedUtc.ToString("o", CultureInfo.InvariantCulture) },
                { "signature_status", file.SignatureStatus ?? string.Empty },
                { "signature_subject", file.SignatureSubject ?? string.Empty }
            };

            if (!string.IsNullOrWhiteSpace(file.Sha256))
            {
                details["sha256"] = file.Sha256;
            }

            return details;
        }

        private static void AddSignatureDetails(string path, IDictionary<string, string> details)
        {
            SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(path);
            details["signature_status"] = signature.Status ?? string.Empty;
            details["signature_subject"] = signature.Subject ?? string.Empty;
            details["winverifytrust_status"] = signature.WinVerifyTrustStatus.ToString(CultureInfo.InvariantCulture);
        }

        private static bool IsUntrusted(DriverFileRecord record)
        {
            return record != null && !string.Equals(record.SignatureStatus, "Trusted", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsWindowsCoreModule(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return FileClassifier.IsUnder(path, Path.Combine(windows, "System32")) ||
                   FileClassifier.IsUnder(path, Path.Combine(windows, "SysWOW64"));
        }

        private static IEnumerable<string> BuildDriverWatchRoots()
        {
            foreach (string root in BuildDriverScanRoots())
            {
                yield return root;
            }

            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop");
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");
            yield return Path.GetTempPath();
        }

        private static IEnumerable<string> BuildDriverScanRoots()
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            yield return Path.Combine(windows, "System32", "drivers");
            yield return Path.Combine(windows, "Temp");
            yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        }

        private static string TrySha256(string path)
        {
            try
            {
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(stream);
                    StringBuilder builder = new StringBuilder(hash.Length * 2);
                    foreach (byte b in hash)
                    {
                        builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                    }

                    return builder.ToString();
                }
            }
            catch
            {
                return null;
            }
        }

        public void Dispose()
        {
            _stopSignal.Set();

            foreach (FileSystemWatcher watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch
                {
                }
            }

            if (_thread != null && _thread.IsAlive)
            {
                _thread.Join(TimeSpan.FromSeconds(2));
            }

            _stopSignal.Dispose();
        }

        private sealed class DriverDropRecord
        {
            public string Path { get; set; }

            public DateTime CreatedUtc { get; set; }

            public DriverFileRecord FileRecord { get; set; }
        }
    }
}
