using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class DefensiveIntegrityMonitor : IDetectionMonitor
    {
        private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
        private static readonly TimeSpan ProcessShortLifeWindow = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan TelemetryDropWindow = TimeSpan.FromMinutes(10);

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private readonly Dictionary<string, FileBaseline> _fileBaselines = new Dictionary<string, FileBaseline>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<int, ProcessStartRecord> _recentProcessStarts = new ConcurrentDictionary<int, ProcessStartRecord>();
        private readonly ConcurrentDictionary<string, DateTime> _lastEventByCategory = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private readonly object _syncRoot = new object();
        private readonly string _baseDirectory;
        private readonly string _logRoot;
        private readonly int _selfProcessId;
        private readonly int _baselineThreadCount;
        private Thread _thread;
        private bool _disposed;
        private bool _sysmonPresentAtStart;

        public DefensiveIntegrityMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _logRoot = Path.GetDirectoryName(logger.JsonLogPath);
            _baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            _selfProcessId = Process.GetCurrentProcess().Id;
            _baselineThreadCount = SafeCurrentThreadCount();
        }

        public string Name
        {
            get { return "Defensive Integrity"; }
        }

        public void Start()
        {
            if (!_options.DefensiveIntegrityEnabled)
            {
                _logger.Log(DetectionEvent.Create(
                    "DefensiveIntegrity",
                    "Disabled",
                    EventSeverity.Low,
                    "Defensive integrity monitoring is disabled by configuration.",
                    null,
                    null,
                    null));
                return;
            }

            BuildSelfIntegrityBaseline();
            TryStartWatcher(_baseDirectory, "CoreDirectory", false);
            TryStartWatcher(_logRoot, "EvidenceDirectory", true);
            _sysmonPresentAtStart = IsSysmonServicePresentOrRunning();
            _logger.EventLogged += OnEventLogged;

            _thread = new Thread(ThreadMain)
            {
                IsBackground = true,
                Name = "Aegis Defensive Integrity Monitor"
            };
            _thread.Start();

            _logger.Log(DetectionEvent.Create(
                "DefensiveIntegrity",
                "Started",
                EventSeverity.Low,
                "Defensive integrity and anti-tamper monitor started in evidence-only mode.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "self_process_id", _selfProcessId.ToString(CultureInfo.InvariantCulture) },
                    { "baseline_file_count", _fileBaselines.Count.ToString(CultureInfo.InvariantCulture) },
                    { "baseline_thread_count", _baselineThreadCount.ToString(CultureInfo.InvariantCulture) },
                    { "scan_interval_seconds", _options.DefensiveIntegrityScanInterval.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "log_hash_chain", _logger.HashChainPath },
                    { "safety_rule", "Detect and preserve evidence only; no killing, blocking, patching, hooks, stealth, or bypass behavior." }
                }));
        }

        private void ThreadMain()
        {
            while (!_stopSignal.Wait(_options.DefensiveIntegrityScanInterval))
            {
                try
                {
                    VerifySelfIntegrity();
                    ScanHandlesToSelf();
                    CheckSelfThreadHealth();
                    CheckTelemetryHealth();
                    CheckSysmonHealth();
                    CleanupProcessStarts();
                }
                catch (Exception ex)
                {
                    _logger.LogException("DefensiveIntegrity", "ScanFailed", ex, null);
                }
            }
        }

        private void BuildSelfIntegrityBaseline()
        {
            AddBaseline(Process.GetCurrentProcess().MainModule.FileName, "core_binary");
            AddBaseline(AppDomain.CurrentDomain.SetupInformation.ConfigurationFile, "core_config");

            try
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    try
                    {
                        if (FileClassifier.IsUnder(module.FileName, _baseDirectory))
                        {
                            AddBaseline(module.FileName, "loaded_module");
                        }
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }

            foreach (string path in Directory.EnumerateFiles(_baseDirectory, "*", SearchOption.TopDirectoryOnly))
            {
                string extension = Path.GetExtension(path);
                if (extension.Equals(".config", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals(".xml", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals(".rules", StringComparison.OrdinalIgnoreCase))
                {
                    AddBaseline(path, "config_or_rules");
                }
            }
        }

        private void AddBaseline(string path, string role)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    return;
                }

                FileInfo info = new FileInfo(path);
                _fileBaselines[path] = new FileBaseline
                {
                    Path = path,
                    Role = role,
                    SizeBytes = info.Length,
                    ModifiedUtc = info.LastWriteTimeUtc,
                    Sha256 = TrySha256(path) ?? string.Empty
                };
            }
            catch
            {
            }
        }

        private void VerifySelfIntegrity()
        {
            foreach (FileBaseline baseline in _fileBaselines.Values.ToArray())
            {
                if (!File.Exists(baseline.Path))
                {
                    EmitOnce(
                        "self_missing|" + baseline.Path,
                        "SelfIntegrityFileMissing",
                        EventSeverity.Critical,
                        "Core AnyWhere file is missing: " + baseline.Path,
                        baseline.Path,
                        new Dictionary<string, string>
                        {
                            { "role", baseline.Role },
                            { "baseline_sha256", baseline.Sha256 }
                        });
                    continue;
                }

                FileInfo info = new FileInfo(baseline.Path);
                bool metadataChanged = info.Length != baseline.SizeBytes || info.LastWriteTimeUtc != baseline.ModifiedUtc;
                string currentHash = metadataChanged ? TrySha256(baseline.Path) : baseline.Sha256;
                if (!string.Equals(currentHash, baseline.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    EmitOnce(
                        "self_changed|" + baseline.Path + "|" + currentHash,
                        "SelfIntegrityHashChanged",
                        baseline.Role.Equals("core_binary", StringComparison.OrdinalIgnoreCase) ? EventSeverity.Critical : EventSeverity.High,
                        "Core AnyWhere file hash changed: " + baseline.Path,
                        baseline.Path,
                        new Dictionary<string, string>
                        {
                            { "role", baseline.Role },
                            { "baseline_sha256", baseline.Sha256 },
                            { "current_sha256", currentHash ?? string.Empty },
                            { "baseline_size", baseline.SizeBytes.ToString(CultureInfo.InvariantCulture) },
                            { "current_size", info.Length.ToString(CultureInfo.InvariantCulture) },
                            { "baseline_modified_utc", baseline.ModifiedUtc.ToString("o", CultureInfo.InvariantCulture) },
                            { "current_modified_utc", info.LastWriteTimeUtc.ToString("o", CultureInfo.InvariantCulture) }
                        });
                }
            }
        }

        private void ScanHandlesToSelf()
        {
            if (_options.MaxSelfHandleScan <= 0)
            {
                return;
            }

            IntPtr buffer = IntPtr.Zero;
            try
            {
                int length = 1024 * 1024;
                int returnedLength;
                int status;

                for (int attempt = 0; attempt < 6; attempt++)
                {
                    buffer = Marshal.AllocHGlobal(length);
                    status = NativeMethods.NtQuerySystemInformation(NativeMethods.SystemExtendedHandleInformation, buffer, length, out returnedLength);
                    if (status == 0)
                    {
                        break;
                    }

                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;

                    if (status != STATUS_INFO_LENGTH_MISMATCH)
                    {
                        return;
                    }

                    length = Math.Max(length * 2, returnedLength + 1024);
                }

                if (buffer == IntPtr.Zero)
                {
                    return;
                }

                long handleCount = Marshal.ReadIntPtr(buffer).ToInt64();
                IntPtr entryPtr = IntPtr.Add(buffer, IntPtr.Size * 2);
                int entrySize = Marshal.SizeOf(typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                int inspected = 0;

                for (long i = 0; i < handleCount && inspected < _options.MaxSelfHandleScan; i++)
                {
                    NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry =
                        (NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(entryPtr, typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                    entryPtr = IntPtr.Add(entryPtr, entrySize);
                    inspected++;

                    int sourcePid = unchecked((int)entry.UniqueProcessId.ToUInt64());
                    if (sourcePid <= 4 || sourcePid == _selfProcessId)
                    {
                        continue;
                    }

                    TryInspectSelfHandle(sourcePid, entry);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private void TryInspectSelfHandle(int sourcePid, NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry)
        {
            uint suspiciousAccess = entry.GrantedAccess & SuspiciousSelfAccessMask();
            if (suspiciousAccess == 0)
            {
                return;
            }

            IntPtr sourceProcessHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_DUP_HANDLE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, sourcePid);
            if (sourceProcessHandle == IntPtr.Zero)
            {
                return;
            }

            IntPtr duplicatedHandle = IntPtr.Zero;
            try
            {
                if (!NativeMethods.DuplicateHandle(
                    sourceProcessHandle,
                    new IntPtr(unchecked((long)entry.HandleValue.ToUInt64())),
                    NativeMethods.GetCurrentProcess(),
                    out duplicatedHandle,
                    0,
                    false,
                    NativeMethods.DUPLICATE_SAME_ACCESS))
                {
                    return;
                }

                string objectType = QueryObjectString(duplicatedHandle, NativeMethods.ObjectTypeInformation);
                if (!string.Equals(objectType, "Process", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                if (NativeMethods.GetProcessId(duplicatedHandle) != _selfProcessId)
                {
                    return;
                }

                string key = "self_handle|" + sourcePid.ToString(CultureInfo.InvariantCulture) + "|" + entry.GrantedAccess.ToString("X", CultureInfo.InvariantCulture);
                ProcessIdentity source = QueryProcess(sourcePid);
                SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(source.Path);
                EventSeverity severity = IsWriteOrTerminateAccess(entry.GrantedAccess) || !signature.IsTrusted ? EventSeverity.Critical : EventSeverity.High;

                EmitOnce(
                    key,
                    "SuspiciousHandleToAnyWhere",
                    severity,
                    "Process has a suspicious handle to AnyWhere: " + (source.Name ?? sourcePid.ToString(CultureInfo.InvariantCulture)),
                    source.Path,
                    new Dictionary<string, string>
                    {
                        { "source_process_id", sourcePid.ToString(CultureInfo.InvariantCulture) },
                        { "source_process_name", source.Name ?? string.Empty },
                        { "source_path", source.Path ?? string.Empty },
                        { "source_sha256", TrySha256(source.Path) ?? string.Empty },
                        { "source_signature_status", signature.Status ?? string.Empty },
                        { "source_signature_subject", signature.Subject ?? string.Empty },
                        { "target_process_id", _selfProcessId.ToString(CultureInfo.InvariantCulture) },
                        { "granted_access", "0x" + entry.GrantedAccess.ToString("X", CultureInfo.InvariantCulture) },
                        { "decoded_access", DecodeProcessAccess(entry.GrantedAccess) },
                        { "tamper_risk", ClassifySelfAccessRisk(entry.GrantedAccess) }
                    });
            }
            catch
            {
            }
            finally
            {
                if (duplicatedHandle != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(duplicatedHandle);
                }

                NativeMethods.CloseHandle(sourceProcessHandle);
            }
        }

        private void CheckSelfThreadHealth()
        {
            int currentCount = SafeCurrentThreadCount();
            if (_baselineThreadCount > 0 && currentCount > 0 && currentCount < Math.Max(2, _baselineThreadCount / 2))
            {
                EmitOnce(
                    "thread_count_drop|" + currentCount.ToString(CultureInfo.InvariantCulture),
                    "MonitorThreadCountDrop",
                    EventSeverity.High,
                    "AnyWhere thread count dropped sharply compared with startup baseline.",
                    null,
                    new Dictionary<string, string>
                    {
                        { "baseline_thread_count", _baselineThreadCount.ToString(CultureInfo.InvariantCulture) },
                        { "current_thread_count", currentCount.ToString(CultureInfo.InvariantCulture) },
                        { "visibility", "User-mode thread health heuristic; individual managed monitor thread names are not exposed by ProcessThread." }
                    });
            }

            try
            {
                using (Process process = Process.GetCurrentProcess())
                {
                    foreach (ProcessThread thread in process.Threads)
                    {
                        try
                        {
                            if (thread.ThreadState == System.Diagnostics.ThreadState.Wait &&
                                thread.WaitReason == ThreadWaitReason.Suspended)
                            {
                                EmitOnce(
                                    "suspended_thread|" + thread.Id.ToString(CultureInfo.InvariantCulture),
                                    "AnyWhereThreadSuspended",
                                    EventSeverity.Critical,
                                    "A thread in AnyWhere appears suspended.",
                                    null,
                                    new Dictionary<string, string>
                                    {
                                        { "thread_id", thread.Id.ToString(CultureInfo.InvariantCulture) },
                                        { "thread_state", thread.ThreadState.ToString() },
                                        { "wait_reason", thread.WaitReason.ToString() }
                                    });
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private void CheckTelemetryHealth()
        {
            DateTime now = DateTime.UtcNow;
            string[] expectedCategories =
            {
                "Process",
                "EventLog",
                "Memory",
                "HiddenKernel",
                "TargetInteraction",
                "KernelComm"
            };

            foreach (string category in expectedCategories)
            {
                DateTime last;
                if (_lastEventByCategory.TryGetValue(category, out last) &&
                    now.Subtract(last) > TelemetryDropWindow)
                {
                    EmitOnce(
                        "telemetry_drop|" + category + "|" + last.ToString("o", CultureInfo.InvariantCulture),
                        "TelemetryVolumeDrop",
                        EventSeverity.Medium,
                        "Expected telemetry category has been quiet longer than normal: " + category,
                        null,
                        new Dictionary<string, string>
                        {
                            { "category", category },
                            { "last_event_utc", last.ToString("o", CultureInfo.InvariantCulture) },
                            { "drop_window_seconds", TelemetryDropWindow.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                            { "interpretation", "May indicate idle system, disabled collector, event provider failure, or telemetry hiding." }
                        });
                }
            }
        }

        private void CheckSysmonHealth()
        {
            if (!_sysmonPresentAtStart)
            {
                return;
            }

            if (!IsSysmonServicePresentOrRunning())
            {
                EmitOnce(
                    "sysmon_disappeared",
                    "SysmonDisappeared",
                    EventSeverity.High,
                    "Sysmon was present at startup but is no longer visible/running.",
                    null,
                    new Dictionary<string, string>
                    {
                        { "startup_state", "present_or_running" },
                        { "current_state", "missing_or_stopped" }
                    });
            }
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed || detectionEvent == null || detectionEvent.Category.StartsWith("DefensiveIntegrity", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            _lastEventByCategory[detectionEvent.Category] = DateTime.UtcNow;
            string root = detectionEvent.Category.Split('.')[0];
            _lastEventByCategory[root] = DateTime.UtcNow;

            DetectTelemetryFailureEvent(detectionEvent);
            DetectEventLogTampering(detectionEvent);
            DetectAntiEvasionHeuristics(detectionEvent);
        }

        private void DetectTelemetryFailureEvent(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Action.IndexOf("SubscriptionFailed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                detectionEvent.Action.IndexOf("DeliveryFailed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                detectionEvent.Action.IndexOf("WatcherError", StringComparison.OrdinalIgnoreCase) >= 0 ||
                detectionEvent.Action.IndexOf("ScanFailed", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                EmitOnce(
                    "collector_failure|" + detectionEvent.Category + "|" + detectionEvent.Action + "|" + detectionEvent.Path,
                    "TelemetryCollectorFailure",
                    EventSeverity.High,
                    "A telemetry collector reported failure: " + detectionEvent.Category + "/" + detectionEvent.Action,
                    detectionEvent.Path,
                    new Dictionary<string, string>
                    {
                        { "source_category", detectionEvent.Category },
                        { "source_action", detectionEvent.Action },
                        { "source_description", detectionEvent.Description }
                    });
            }
        }

        private void DetectEventLogTampering(DetectionEvent detectionEvent)
        {
            string text = (detectionEvent.Category + " " + detectionEvent.Action + " " + detectionEvent.Description + " " +
                          detectionEvent.Path + " " + string.Join(" ", detectionEvent.Details.Values.ToArray())).ToLowerInvariant();

            if (detectionEvent.Action.Equals("AuditLogCleared", StringComparison.OrdinalIgnoreCase) ||
                text.IndexOf("event log was cleared", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                EmitLinkedTamperEvent("EventLogCleared", EventSeverity.Critical, "Event log clearing was observed.", detectionEvent);
            }

            if (detectionEvent.Action.Equals("AuditPolicyChanged", StringComparison.OrdinalIgnoreCase) ||
                text.IndexOf("audit policy", StringComparison.OrdinalIgnoreCase) >= 0 && ContainsWeakeningTerms(text))
            {
                EmitLinkedTamperEvent("AuditPolicyWeakening", EventSeverity.High, "Audit policy weakening or modification was observed.", detectionEvent);
            }

            if ((text.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) >= 0 && text.IndexOf("scriptblocklogging", StringComparison.OrdinalIgnoreCase) >= 0 && ContainsWeakeningTerms(text)) ||
                text.IndexOf("enabletranscripting dword:0", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                EmitLinkedTamperEvent("PowerShellLoggingDisabled", EventSeverity.High, "PowerShell logging appears to have been weakened or disabled.", detectionEvent);
            }

            if (text.IndexOf("windows defender\\exclusions", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("defender exclusion", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                EmitLinkedTamperEvent("DefenderExclusionAddedOrChanged", EventSeverity.High, "Microsoft Defender exclusion path/process setting changed.", detectionEvent);
            }

            if (text.IndexOf("codeintegrity", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("\\control\\ci", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                EmitLinkedTamperEvent("CodeIntegrityPolicyChanged", EventSeverity.High, "Code Integrity policy/configuration changed.", detectionEvent);
            }

            if (text.IndexOf("sysmon", StringComparison.OrdinalIgnoreCase) >= 0 &&
                (text.IndexOf("config", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 text.IndexOf("configuration", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 text.IndexOf("servicestatechange", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                EmitLinkedTamperEvent("SysmonConfigurationChanged", EventSeverity.High, "Sysmon configuration or service state change was observed.", detectionEvent);
            }
        }

        private void EmitLinkedTamperEvent(string action, EventSeverity severity, string description, DetectionEvent source)
        {
            EmitOnce(
                "linked|" + action + "|" + source.Category + "|" + source.Action + "|" + source.Path,
                action,
                severity,
                description,
                source.Path,
                new Dictionary<string, string>
                {
                    { "source_category", source.Category },
                    { "source_action", source.Action },
                    { "source_description", source.Description },
                    { "source_process_id", source.ProcessId.HasValue ? source.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty },
                    { "source_process_name", source.ProcessName ?? string.Empty }
                });
        }

        private void DetectAntiEvasionHeuristics(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Category.Equals("Process", StringComparison.OrdinalIgnoreCase) &&
                detectionEvent.Action.Equals("Executed", StringComparison.OrdinalIgnoreCase))
            {
                TrackProcessStart(detectionEvent);
                DetectSuspiciousParentChain(detectionEvent);
                DetectRenamedLolbinOrFakeSigner(detectionEvent);
            }
            else if (detectionEvent.Category.Equals("Process", StringComparison.OrdinalIgnoreCase) &&
                     detectionEvent.Action.Equals("Exited", StringComparison.OrdinalIgnoreCase))
            {
                DetectShortLivedProcess(detectionEvent);
            }

            if (detectionEvent.Action.IndexOf("Renamed", StringComparison.OrdinalIgnoreCase) >= 0 &&
                FileClassifier.IsLikelyExecutable(detectionEvent.Path))
            {
                EmitLinkedTamperEvent("ExecutableRenamed", EventSeverity.Medium, "Executable/script rename activity was observed.", detectionEvent);
            }

            if (detectionEvent.Action.IndexOf("ShortLivedDriverFileDeleted", StringComparison.OrdinalIgnoreCase) >= 0 ||
                detectionEvent.Action.IndexOf("UntrustedDriverDropped", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                EmitLinkedTamperEvent("TransientDriverArtifact", EventSeverity.High, "Transient or untrusted driver artifact was observed.", detectionEvent);
            }

            DetectTimestomping(detectionEvent);
        }

        private void TrackProcessStart(DetectionEvent detectionEvent)
        {
            if (!detectionEvent.ProcessId.HasValue)
            {
                return;
            }

            _recentProcessStarts[detectionEvent.ProcessId.Value] = new ProcessStartRecord
            {
                ProcessId = detectionEvent.ProcessId.Value,
                ProcessName = detectionEvent.ProcessName,
                Path = detectionEvent.Path,
                ParentProcessName = Detail(detectionEvent, "parent_process_name"),
                ParentProcessId = Detail(detectionEvent, "parent_process_id"),
                CommandLine = Detail(detectionEvent, "command_line"),
                StartedUtc = DateTime.UtcNow,
                Suspicious = detectionEvent.Severity >= EventSeverity.High || IsSuspiciousCommandLine(Detail(detectionEvent, "command_line"))
            };
        }

        private void DetectShortLivedProcess(DetectionEvent detectionEvent)
        {
            if (!detectionEvent.ProcessId.HasValue)
            {
                return;
            }

            ProcessStartRecord start;
            if (!_recentProcessStarts.TryRemove(detectionEvent.ProcessId.Value, out start))
            {
                return;
            }

            TimeSpan lifetime = DateTime.UtcNow.Subtract(start.StartedUtc);
            if (lifetime <= ProcessShortLifeWindow && start.Suspicious)
            {
                EmitOnce(
                    "short_lived_process|" + start.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + start.Path,
                    "ShortLivedSuspiciousProcess",
                    EventSeverity.High,
                    "Suspicious process exited shortly after launch: " + start.ProcessName,
                    start.Path,
                    new Dictionary<string, string>
                    {
                        { "process_id", start.ProcessId.ToString(CultureInfo.InvariantCulture) },
                        { "process_name", start.ProcessName ?? string.Empty },
                        { "path", start.Path ?? string.Empty },
                        { "parent_process_id", start.ParentProcessId ?? string.Empty },
                        { "parent_process_name", start.ParentProcessName ?? string.Empty },
                        { "lifetime_seconds", lifetime.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture) },
                        { "command_line", start.CommandLine ?? string.Empty }
                    });
            }
        }

        private void DetectSuspiciousParentChain(DetectionEvent detectionEvent)
        {
            string parent = Detail(detectionEvent, "parent_process_name");
            string commandLine = Detail(detectionEvent, "command_line");
            string path = detectionEvent.Path;

            if (!IsLolbin(parent) && !IsSuspiciousCommandLine(commandLine))
            {
                return;
            }

            bool fromRiskyLocation = FileClassifier.IsLikelyDownloadLocation(path) ||
                                     FileClassifier.IsUnder(path, Path.GetTempPath()) ||
                                     FileClassifier.IsUnder(path, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));

            if (fromRiskyLocation || IsSuspiciousCommandLine(commandLine))
            {
                EmitOnce(
                    "parent_chain|" + detectionEvent.ProcessId.GetValueOrDefault().ToString(CultureInfo.InvariantCulture) + "|" + parent,
                    "UnusualParentChildProcessChain",
                    EventSeverity.High,
                    "Potential LOLBIN or unusual parent-child execution chain.",
                    path,
                    new Dictionary<string, string>
                    {
                        { "process_id", detectionEvent.ProcessId.HasValue ? detectionEvent.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty },
                        { "process_name", detectionEvent.ProcessName ?? string.Empty },
                        { "path", path ?? string.Empty },
                        { "parent_process_name", parent ?? string.Empty },
                        { "command_line", commandLine ?? string.Empty }
                    });
            }
        }

        private void DetectRenamedLolbinOrFakeSigner(DetectionEvent detectionEvent)
        {
            string path = detectionEvent.Path;
            string signer = Detail(detectionEvent, "signature_subject");
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            string fileName = Path.GetFileName(path);
            string originalName = TryGetOriginalFileName(path);
            if (!string.IsNullOrWhiteSpace(originalName) &&
                !fileName.Equals(originalName, StringComparison.OrdinalIgnoreCase) &&
                IsLolbin(originalName))
            {
                EmitOnce(
                    "renamed_lolbin|" + path,
                    "RenamedExecutableIdentityMismatch",
                    EventSeverity.High,
                    "Executable original filename differs from on-disk name for a common LOLBIN.",
                    path,
                    new Dictionary<string, string>
                    {
                        { "file_name", fileName },
                        { "original_file_name", originalName },
                        { "signature_subject", signer ?? string.Empty }
                    });
            }

            if (!string.IsNullOrWhiteSpace(signer) &&
                signer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 &&
                FileClassifier.IsLikelyDownloadLocation(path))
            {
                SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(path);
                if (!signature.IsTrusted)
                {
                    EmitOnce(
                        "fake_signer|" + path,
                        "SuspiciousSignerMetadata",
                        EventSeverity.High,
                        "File claims Microsoft-like signer metadata but trust verification failed.",
                        path,
                        new Dictionary<string, string>
                        {
                            { "signature_subject", signer },
                            { "winverifytrust_status", signature.WinVerifyTrustStatus.ToString(CultureInfo.InvariantCulture) },
                            { "signature_status", signature.Status ?? string.Empty }
                        });
                }
            }
        }

        private void DetectTimestomping(DetectionEvent detectionEvent)
        {
            string created = Detail(detectionEvent, "created_utc");
            string modified = Detail(detectionEvent, "modified_utc");
            if (string.IsNullOrWhiteSpace(created) || string.IsNullOrWhiteSpace(modified))
            {
                return;
            }

            DateTime createdUtc;
            DateTime modifiedUtc;
            if (!DateTime.TryParse(created, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out createdUtc) ||
                !DateTime.TryParse(modified, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out modifiedUtc))
            {
                return;
            }

            if (createdUtc.Subtract(modifiedUtc).TotalDays > 30 && FileClassifier.IsLikelyDownloadLocation(detectionEvent.Path))
            {
                EmitOnce(
                    "timestomp|" + detectionEvent.Path,
                    "TimestompingIndicator",
                    EventSeverity.Medium,
                    "Executable in risky location has modification time much older than creation time.",
                    detectionEvent.Path,
                    new Dictionary<string, string>
                    {
                        { "created_utc", created },
                        { "modified_utc", modified },
                        { "delta_days", createdUtc.Subtract(modifiedUtc).TotalDays.ToString("0.0", CultureInfo.InvariantCulture) }
                    });
            }
        }

        private void TryStartWatcher(string path, string role, bool includeSubdirectories)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
                {
                    return;
                }

                FileSystemWatcher watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = includeSubdirectories,
                    InternalBufferSize = 64 * 1024,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime | NotifyFilters.Security
                };

                watcher.Changed += delegate(object sender, FileSystemEventArgs args) { OnWatchedPathChanged(role, "Changed", args.FullPath, null); };
                watcher.Created += delegate(object sender, FileSystemEventArgs args) { OnWatchedPathChanged(role, "Created", args.FullPath, null); };
                watcher.Deleted += delegate(object sender, FileSystemEventArgs args) { OnWatchedPathChanged(role, "Deleted", args.FullPath, null); };
                watcher.Renamed += delegate(object sender, RenamedEventArgs args) { OnWatchedPathChanged(role, "Renamed", args.FullPath, args.OldFullPath); };
                watcher.Error += delegate(object sender, ErrorEventArgs args)
                {
                    _logger.LogException("DefensiveIntegrity", "FileWatcherError", args.GetException(), role);
                };

                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogException("DefensiveIntegrity", "WatcherStartFailed", ex, path);
            }
        }

        private void OnWatchedPathChanged(string role, string action, string path, string oldPath)
        {
            if (_disposed || string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            bool core = role.Equals("CoreDirectory", StringComparison.OrdinalIgnoreCase) && IsCorePath(path);
            bool evidenceTamper = role.Equals("EvidenceDirectory", StringComparison.OrdinalIgnoreCase) &&
                                  (action.Equals("Deleted", StringComparison.OrdinalIgnoreCase) ||
                                   action.Equals("Renamed", StringComparison.OrdinalIgnoreCase));

            if (!core && !evidenceTamper)
            {
                return;
            }

            string key = "watch|" + role + "|" + action + "|" + path + "|" + oldPath;
            EmitOnce(
                key,
                core ? "CoreFileChanged" : "EvidencePathTampered",
                core ? EventSeverity.High : EventSeverity.Critical,
                core ? "AnyWhere core/config/rules path changed." : "AnyWhere log/evidence path was deleted or renamed.",
                path,
                new Dictionary<string, string>
                {
                    { "watch_role", role },
                    { "file_action", action },
                    { "path", path },
                    { "old_path", oldPath ?? string.Empty },
                    { "exists", File.Exists(path).ToString() }
                });
        }

        private bool IsCorePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string extension = Path.GetExtension(path);
            return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".config", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".xml", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".rules", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsSysmonServicePresentOrRunning()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT Name, State FROM Win32_Service WHERE Name='Sysmon' OR Name='Sysmon64' OR Name='SysmonDrv'"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        using (obj)
                        {
                            string state = Convert.ToString(obj["State"], CultureInfo.InvariantCulture);
                            return string.IsNullOrWhiteSpace(state) ||
                                   state.Equals("Running", StringComparison.OrdinalIgnoreCase) ||
                                   state.Equals("Start Pending", StringComparison.OrdinalIgnoreCase);
                        }
                    }
                }
            }
            catch
            {
            }

            return false;
        }

        private ProcessIdentity QueryProcess(int processId)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = " +
                    processId.ToString(CultureInfo.InvariantCulture)))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        using (obj)
                        {
                            return new ProcessIdentity
                            {
                                ProcessId = processId,
                                ParentProcessId = Convert.ToInt32(obj["ParentProcessId"], CultureInfo.InvariantCulture),
                                Name = Convert.ToString(obj["Name"], CultureInfo.InvariantCulture),
                                Path = Convert.ToString(obj["ExecutablePath"], CultureInfo.InvariantCulture),
                                CommandLine = Convert.ToString(obj["CommandLine"], CultureInfo.InvariantCulture)
                            };
                        }
                    }
                }
            }
            catch
            {
            }

            return new ProcessIdentity
            {
                ProcessId = processId,
                Name = TryGetProcessName(processId),
                Path = TryGetProcessPath(processId)
            };
        }

        private void EmitOnce(string key, string action, EventSeverity severity, string description, string path, Dictionary<string, string> details)
        {
            lock (_syncRoot)
            {
                if (!_reportedKeys.Add(key))
                {
                    return;
                }
            }

            if (details == null)
            {
                details = new Dictionary<string, string>();
            }

            details["evidence_mode"] = "Detection and preservation only.";
            _logger.Log(DetectionEvent.Create(
                "DefensiveIntegrity",
                action,
                severity,
                description,
                path,
                null,
                details));
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

                    buffer = Marshal.AllocHGlobal(returnedLength);
                    status = NativeMethods.NtQueryObject(handle, informationClass, buffer, returnedLength, out returnedLength);
                    if (status != 0)
                    {
                        return null;
                    }
                }

                NativeMethods.UNICODE_STRING unicodeString =
                    (NativeMethods.UNICODE_STRING)Marshal.PtrToStructure(buffer, typeof(NativeMethods.UNICODE_STRING));
                return unicodeString.Length == 0 || unicodeString.Buffer == IntPtr.Zero
                    ? null
                    : Marshal.PtrToStringUni(unicodeString.Buffer, unicodeString.Length / 2);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private static uint SuspiciousSelfAccessMask()
        {
            return NativeMethods.PROCESS_TERMINATE |
                   NativeMethods.PROCESS_VM_READ |
                   NativeMethods.PROCESS_VM_WRITE |
                   NativeMethods.PROCESS_VM_OPERATION |
                   NativeMethods.PROCESS_CREATE_THREAD |
                   NativeMethods.PROCESS_DUP_HANDLE |
                   NativeMethods.PROCESS_SET_INFORMATION |
                   NativeMethods.PROCESS_SUSPEND_RESUME;
        }

        private static bool IsWriteOrTerminateAccess(uint access)
        {
            return (access & NativeMethods.PROCESS_TERMINATE) != 0 ||
                   (access & NativeMethods.PROCESS_VM_WRITE) != 0 ||
                   (access & NativeMethods.PROCESS_VM_OPERATION) != 0 ||
                   (access & NativeMethods.PROCESS_CREATE_THREAD) != 0 ||
                   (access & NativeMethods.PROCESS_SUSPEND_RESUME) != 0;
        }

        private static string ClassifySelfAccessRisk(uint access)
        {
            List<string> risks = new List<string>();
            if ((access & NativeMethods.PROCESS_TERMINATE) != 0) risks.Add("terminate");
            if ((access & NativeMethods.PROCESS_SUSPEND_RESUME) != 0) risks.Add("suspend_resume");
            if ((access & NativeMethods.PROCESS_CREATE_THREAD) != 0) risks.Add("remote_thread");
            if ((access & NativeMethods.PROCESS_VM_WRITE) != 0 || (access & NativeMethods.PROCESS_VM_OPERATION) != 0) risks.Add("memory_patch_or_injection");
            if ((access & NativeMethods.PROCESS_DUP_HANDLE) != 0) risks.Add("handle_duplication_or_closure");
            if ((access & NativeMethods.PROCESS_VM_READ) != 0) risks.Add("memory_read");
            return string.Join("|", risks.ToArray());
        }

        private static string DecodeProcessAccess(uint access)
        {
            List<string> rights = new List<string>();
            AddRight(rights, access, NativeMethods.PROCESS_TERMINATE, "PROCESS_TERMINATE");
            AddRight(rights, access, NativeMethods.PROCESS_VM_READ, "PROCESS_VM_READ");
            AddRight(rights, access, NativeMethods.PROCESS_VM_WRITE, "PROCESS_VM_WRITE");
            AddRight(rights, access, NativeMethods.PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION");
            AddRight(rights, access, NativeMethods.PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD");
            AddRight(rights, access, NativeMethods.PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE");
            AddRight(rights, access, NativeMethods.PROCESS_SET_INFORMATION, "PROCESS_SET_INFORMATION");
            AddRight(rights, access, NativeMethods.PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION");
            AddRight(rights, access, NativeMethods.PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME");
            return rights.Count == 0 ? "0x" + access.ToString("X", CultureInfo.InvariantCulture) : string.Join("|", rights.ToArray());
        }

        private static void AddRight(ICollection<string> rights, uint access, uint mask, string name)
        {
            if ((access & mask) == mask)
            {
                rights.Add(name);
            }
        }

        private static bool ContainsWeakeningTerms(string text)
        {
            return text.IndexOf("disable", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   text.IndexOf("disabled", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   text.IndexOf("remove", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   text.IndexOf("success and failure removed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   text.IndexOf("dword:0", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   text.IndexOf("0x0", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsSuspiciousCommandLine(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                return false;
            }

            string text = commandLine.ToLowerInvariant();
            string[] terms =
            {
                " -enc", " encodedcommand", "frombase64string", "downloadstring", "invoke-webrequest",
                "bitsadmin", "certutil", "reg add", "wevtutil cl", "auditpol /set", "add-mppreference",
                "set-mppreference", "sc stop sysmon", "sysmon -c", "vssadmin delete", "bcdedit /set testsigning"
            };

            foreach (string term in terms)
            {
                if (text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsLolbin(string processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
            {
                return false;
            }

            string name = Path.GetFileName(processName).ToLowerInvariant();
            string[] names =
            {
                "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe", "wmic.exe",
                "certutil.exe", "bitsadmin.exe", "reg.exe", "schtasks.exe", "sc.exe", "wevtutil.exe"
            };

            return names.Contains(name, StringComparer.OrdinalIgnoreCase);
        }

        private static string TryGetOriginalFileName(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    return null;
                }

                FileVersionInfo info = FileVersionInfo.GetVersionInfo(path);
                return info == null ? null : info.OriginalFilename;
            }
            catch
            {
                return null;
            }
        }

        private static int SafeCurrentThreadCount()
        {
            try
            {
                using (Process process = Process.GetCurrentProcess())
                {
                    return process.Threads.Count;
                }
            }
            catch
            {
                return 0;
            }
        }

        private static string Detail(DetectionEvent detectionEvent, string key)
        {
            string value;
            return detectionEvent.Details != null && detectionEvent.Details.TryGetValue(key, out value) ? value : string.Empty;
        }

        private static string TryGetProcessPath(int processId)
        {
            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    return process.MainModule.FileName;
                }
            }
            catch
            {
                return null;
            }
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

        private static string TrySha256(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    return null;
                }

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

        private void CleanupProcessStarts()
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(TimeSpan.FromMinutes(30));
            foreach (KeyValuePair<int, ProcessStartRecord> pair in _recentProcessStarts.ToArray())
            {
                if (pair.Value.StartedUtc < cutoff)
                {
                    ProcessStartRecord ignored;
                    _recentProcessStarts.TryRemove(pair.Key, out ignored);
                }
            }
        }

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
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

        private sealed class FileBaseline
        {
            public string Path { get; set; }
            public string Role { get; set; }
            public long SizeBytes { get; set; }
            public DateTime ModifiedUtc { get; set; }
            public string Sha256 { get; set; }
        }

        private sealed class ProcessIdentity
        {
            public int ProcessId { get; set; }
            public int ParentProcessId { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
            public string CommandLine { get; set; }
        }

        private sealed class ProcessStartRecord
        {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string Path { get; set; }
            public string ParentProcessId { get; set; }
            public string ParentProcessName { get; set; }
            public string CommandLine { get; set; }
            public DateTime StartedUtc { get; set; }
            public bool Suspicious { get; set; }
        }
    }
}
