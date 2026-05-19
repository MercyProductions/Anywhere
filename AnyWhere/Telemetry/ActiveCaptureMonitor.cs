using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace AnyWhere.Telemetry
{
    internal sealed class ActiveCaptureMonitor : IDetectionMonitor
    {
        private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(10);
        private static readonly HashSet<string> EvidenceExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".cpl", ".ocx", ".drv",
            ".ini", ".cfg", ".conf", ".json", ".xml", ".yaml", ".yml", ".txt", ".dat", ".bin"
        };

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ConcurrentQueue<RecentSignal> _recentSignals = new ConcurrentQueue<RecentSignal>();
        private readonly ConcurrentDictionary<string, DateTime> _captureTimesByKey = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly object _cleanupLock = new object();
        private readonly string _captureRoot;
        private volatile bool _disposed;

        public ActiveCaptureMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _captureRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Active Capture Cases");
        }

        public string Name
        {
            get { return "Active Capture"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_captureRoot);
            _logger.EventLogged += OnEventLogged;

            _logger.Log(DetectionEvent.Create(
                "ActiveCapture",
                _options.ActiveCaptureEnabled ? "Started" : "Disabled",
                EventSeverity.Low,
                _options.ActiveCaptureEnabled
                    ? "Active Capture mode is armed in evidence-only mode."
                    : "Active Capture mode is disabled by configuration.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "capture_root", _captureRoot },
                    { "cooldown_seconds", _options.ActiveCaptureCooldown.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "max_handles", _options.ActiveCaptureMaxHandlesToInspect.ToString(CultureInfo.InvariantCulture) },
                    { "event_log_minutes", _options.ActiveCaptureEventLogMinutes.ToString(CultureInfo.InvariantCulture) },
                    { "safety_rule", "Evidence only: no killing, blocking, patching, unloading, stealth, or bypass behavior." }
                }));
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed || detectionEvent == null || detectionEvent.Category.StartsWith("ActiveCapture", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            RecentSignal signal = RecentSignal.FromEvent(detectionEvent);
            if (IsRelevant(signal))
            {
                _recentSignals.Enqueue(signal);
            }

            CleanupRecentSignals();

            if (!_options.ActiveCaptureEnabled)
            {
                return;
            }

            TriggerDecision decision = EvaluateTrigger(signal);
            if (decision == null)
            {
                return;
            }

            string captureKey = BuildCaptureKey(signal, decision);
            DateTime now = DateTime.UtcNow;
            DateTime previous;
            if (_captureTimesByKey.TryGetValue(captureKey, out previous) &&
                now.Subtract(previous) < _options.ActiveCaptureCooldown)
            {
                return;
            }

            _captureTimesByKey[captureKey] = now;

            CaptureRequest request = BuildCaptureRequest(signal, decision, captureKey);
            ThreadPool.QueueUserWorkItem(delegate
            {
                ExecuteCapture(request);
            });
        }

        private TriggerDecision EvaluateTrigger(RecentSignal signal)
        {
            if (signal == null)
            {
                return null;
            }

            double confidence = signal.ConfidenceScore;
            bool highSignal = signal.Severity >= EventSeverity.High || confidence >= 0.70;
            if (!highSignal)
            {
                return null;
            }

            if (IsUnsignedWriteHandleToTarget(signal))
            {
                return new TriggerDecision("Unsigned process opened protected target with VM_WRITE/VM_OPERATION style rights.", "UnsignedWriteHandleToGame");
            }

            if (ContainsAny(signal.Action, "PrivateExecutableMemory", "RwxPrivateMemory", "PrivatePeHeader"))
            {
                return new TriggerDecision("Protected target gained suspicious private executable memory.", "PrivateExecutableMemoryInTarget");
            }

            if (ContainsAny(signal.Action, "SuspiciousSharedSectionWithTarget"))
            {
                return new TriggerDecision("Suspicious process and protected target share named memory.", "SharedMemoryWithTarget");
            }

            if (ContainsAny(signal.Action, "CommunicationChainCorrelated"))
            {
                return new TriggerDecision("Controller communication chain was correlated with target process evidence.", "CommunicationChain");
            }

            if (HasUnknownDeviceAndTargetAccess(signal))
            {
                return new TriggerDecision("Unknown device or communication object is near protected target access.", "DeviceThenTargetAccess");
            }

            if (HasLoaderAndDroppedExecutable())
            {
                return new TriggerDecision("Suspicious loader activity is near a dropped SYS/DLL/EXE artifact.", "LoaderAndDroppedArtifact");
            }

            if (HasHiddenKernelAndTargetAnomaly())
            {
                return new TriggerDecision("Hidden-kernel indicators are near protected target memory anomalies.", "HiddenKernelAndTargetAnomaly");
            }

            return null;
        }

        private bool IsUnsignedWriteHandleToTarget(RecentSignal signal)
        {
            if (!signal.Category.StartsWith("TargetInteraction", StringComparison.OrdinalIgnoreCase) &&
                !signal.Category.StartsWith("KernelComm", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (signal.Action.IndexOf("Target", StringComparison.OrdinalIgnoreCase) < 0 &&
                signal.Action.IndexOf("ProcessOpenedProtectedTarget", StringComparison.OrdinalIgnoreCase) < 0)
            {
                return false;
            }

            string rights = signal.Detail("decoded_access") + " " + signal.Detail("granted_access") + " " + signal.Detail("access_rights");
            bool writes = rights.IndexOf("PROCESS_VM_WRITE", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          rights.IndexOf("PROCESS_VM_OPERATION", StringComparison.OrdinalIgnoreCase) >= 0 ||
                          rights.IndexOf("PROCESS_CREATE_THREAD", StringComparison.OrdinalIgnoreCase) >= 0;

            string signature = signal.Detail("source_signature_status");
            bool unsigned = string.IsNullOrWhiteSpace(signature) ||
                            signature.IndexOf("Trusted", StringComparison.OrdinalIgnoreCase) < 0;

            return writes && unsigned;
        }

        private bool HasUnknownDeviceAndTargetAccess(RecentSignal signal)
        {
            bool currentDevice = ContainsAny(signal.Action, "SuspiciousDeviceObjectHandle", "SuspiciousDeviceHandle", "WritableExecutableSectionHandle", "SuspiciousSectionHandle") ||
                                 signal.Detail("unsigned_unknown_device").Equals("True", StringComparison.OrdinalIgnoreCase);
            bool currentTarget = ContainsAny(signal.Action, "SuspiciousTargetHandle", "ProcessOpenedProtectedTarget");

            if (currentDevice && HasRecent(s => ContainsAny(s.Action, "SuspiciousTargetHandle", "ProcessOpenedProtectedTarget"), CorrelationWindow))
            {
                return true;
            }

            if (currentTarget && HasRecent(s => ContainsAny(s.Action, "SuspiciousDeviceObjectHandle", "SuspiciousDeviceHandle", "WritableExecutableSectionHandle", "SuspiciousSectionHandle") ||
                                                s.Detail("unsigned_unknown_device").Equals("True", StringComparison.OrdinalIgnoreCase), CorrelationWindow))
            {
                return true;
            }

            return false;
        }

        private bool HasLoaderAndDroppedExecutable()
        {
            bool loader = HasRecent(s => ContainsAny(s.Action, "SuspiciousDriverLoaderProcess") ||
                                         ContainsAny(s.Text, "kdmapper", "drvmap", "manualmap", "loader", "mapper", "vulnerable-driver"), CorrelationWindow);

            bool artifact = HasRecent(s => ContainsAny(s.Action, "UntrustedDriverDropped", "DriverFileCreated", "RecentlyDroppedDriverChanged", "Downloaded", "FileCreated", "ImageLoaded") &&
                                           IsExecutableEvidencePath(s.Path), CorrelationWindow);

            return loader && artifact;
        }

        private bool HasHiddenKernelAndTargetAnomaly()
        {
            bool hidden = HasRecent(s => s.Category.StartsWith("HiddenKernel", StringComparison.OrdinalIgnoreCase) ||
                                         ContainsAny(s.Action, "ServiceRunningModuleMissing", "RecentUntrustedDriverFile", "SuspiciousDeviceHandle"), CorrelationWindow);

            bool target = HasRecent(s => s.Category.StartsWith("TargetInteraction", StringComparison.OrdinalIgnoreCase) &&
                                         ContainsAny(s.Action, "PrivateExecutableMemory", "RwxPrivateMemory", "PrivatePeHeader", "UnsignedMappedDllInTarget", "ThreadStartOutsideKnownModule"), CorrelationWindow);

            return hidden && target;
        }

        private CaptureRequest BuildCaptureRequest(RecentSignal trigger, TriggerDecision decision, string captureKey)
        {
            List<RecentSignal> related = CollectRelatedSignals(trigger);
            HashSet<int> involvedPids = new HashSet<int>();
            HashSet<string> paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (RecentSignal signal in related)
            {
                AddSignalProcessIds(signal, involvedPids);
                AddSignalPaths(signal, paths);
            }

            AddProtectedTargetPids(involvedPids);

            string upstreamCaseId = trigger.Detail("case_id");
            if (string.IsNullOrWhiteSpace(upstreamCaseId))
            {
                upstreamCaseId = trigger.CaseId;
            }

            return new CaptureRequest
            {
                CaptureKey = captureKey,
                CaptureId = "ACAP-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8),
                Trigger = trigger,
                TriggerReason = decision.Reason,
                TriggerKind = decision.Kind,
                UpstreamCaseId = upstreamCaseId,
                RelatedSignals = related,
                InvolvedProcessIds = involvedPids.ToList(),
                CandidatePaths = paths.ToList()
            };
        }

        private void ExecuteCapture(CaptureRequest request)
        {
            string folder = Path.Combine(_captureRoot, SanitizeFileName(request.CaptureId));
            string filesFolder = Path.Combine(folder, "Files");
            Directory.CreateDirectory(folder);
            Directory.CreateDirectory(filesFolder);

            _logger.Log(DetectionEvent.Create(
                "ActiveCapture",
                "CaptureStarted",
                EventSeverity.High,
                "Active Capture started: " + request.TriggerReason,
                request.Trigger.Path,
                null,
                new Dictionary<string, string>
                {
                    { "capture_id", request.CaptureId },
                    { "capture_folder", folder },
                    { "trigger_kind", request.TriggerKind },
                    { "upstream_case_id", request.UpstreamCaseId ?? string.Empty },
                    { "safety_rule", "Evidence only: metadata snapshots and file preservation; no killing, blocking, patching, unloading, stealth, or bypass behavior." }
                }));

            try
            {
                List<Dictionary<string, string>> processTree = CaptureProcessTree(request.InvolvedProcessIds);
                Dictionary<int, ProcessSnapshot> processSnapshots = BuildProcessSnapshots(processTree, request.InvolvedProcessIds);
                List<Dictionary<string, string>> moduleRows = CaptureLoadedModules(request.InvolvedProcessIds);
                MemoryCaptureResult memory = CaptureMemoryMetadata(request.InvolvedProcessIds, processSnapshots);
                List<Dictionary<string, string>> handles = CaptureOpenHandles(request.InvolvedProcessIds);
                List<Dictionary<string, string>> registry = CaptureRegistrySnapshots();
                List<Dictionary<string, string>> artifacts = PreserveArtifacts(request.CandidatePaths, filesFolder);
                List<Dictionary<string, string>> eventLogs = CaptureEventLogExcerpts();
                List<Dictionary<string, string>> timeline = BuildTimelineRows(request.RelatedSignals);

                WriteJsonArray(Path.Combine(folder, "process-tree.json"), processTree);
                WriteJsonArray(Path.Combine(folder, "loaded-modules.json"), moduleRows);
                WriteJsonArray(Path.Combine(folder, "mapped-memory-summary.json"), memory.SummaryRows);
                WriteJsonArray(Path.Combine(folder, "suspicious-memory-regions.json"), memory.SuspiciousRegionRows);
                WriteJsonArray(Path.Combine(folder, "open-handles.json"), handles);
                WriteJsonArray(Path.Combine(folder, "registry-keys.json"), registry);
                WriteJsonArray(Path.Combine(folder, "artifacts.json"), artifacts);
                WriteJsonArray(Path.Combine(folder, "event-log-excerpts.json"), eventLogs);
                WriteJsonArray(Path.Combine(folder, "timeline.json"), timeline);
                WriteSummary(Path.Combine(folder, "summary.txt"), request, processSnapshots, artifacts, memory.SuspiciousRegionRows, handles);
                string manifestPath = CaseIntegrityManifestWriter.WriteManifest(folder);
                string archivePath = _options.EvidenceArchiveEnabled ? CaseIntegrityManifestWriter.TryCreateArchive(folder) : null;
                string mirrorPath = CaseIntegrityManifestWriter.TryMirrorFolder(folder, _options.EvidenceMirrorPath);

                _logger.Log(DetectionEvent.Create(
                    "ActiveCapture",
                    "CaptureCompleted",
                    EventSeverity.High,
                    "Active Capture bundle completed.",
                    folder,
                    null,
                    new Dictionary<string, string>
                    {
                        { "capture_id", request.CaptureId },
                        { "capture_folder", folder },
                        { "trigger_kind", request.TriggerKind },
                        { "process_count", processTree.Count.ToString(CultureInfo.InvariantCulture) },
                        { "involved_process_count", request.InvolvedProcessIds.Count.ToString(CultureInfo.InvariantCulture) },
                        { "module_count", moduleRows.Count.ToString(CultureInfo.InvariantCulture) },
                        { "suspicious_memory_region_count", memory.SuspiciousRegionRows.Count.ToString(CultureInfo.InvariantCulture) },
                        { "handle_count", handles.Count.ToString(CultureInfo.InvariantCulture) },
                        { "artifact_count", artifacts.Count.ToString(CultureInfo.InvariantCulture) },
                        { "event_log_excerpt_count", eventLogs.Count.ToString(CultureInfo.InvariantCulture) },
                        { "integrity_manifest_path", manifestPath ?? string.Empty },
                        { "archive_path", archivePath ?? string.Empty },
                        { "mirror_path", mirrorPath ?? string.Empty }
                    }));
            }
            catch (Exception ex)
            {
                _logger.LogException("ActiveCapture", "CaptureFailed", ex, request.CaptureId);
            }
        }

        private List<Dictionary<string, string>> CaptureProcessTree(ICollection<int> involvedPids)
        {
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            HashSet<int> involved = new HashSet<int>(involvedPids ?? new int[0]);

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate FROM Win32_Process"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        using (obj)
                        {
                            int pid = SafeInt(obj["ProcessId"]);
                            rows.Add(new Dictionary<string, string>
                            {
                                { "process_id", pid.ToString(CultureInfo.InvariantCulture) },
                                { "parent_process_id", SafeInt(obj["ParentProcessId"]).ToString(CultureInfo.InvariantCulture) },
                                { "name", Convert.ToString(obj["Name"], CultureInfo.InvariantCulture) ?? string.Empty },
                                { "path", Convert.ToString(obj["ExecutablePath"], CultureInfo.InvariantCulture) ?? string.Empty },
                                { "command_line", Convert.ToString(obj["CommandLine"], CultureInfo.InvariantCulture) ?? string.Empty },
                                { "creation_utc", ConvertWmiDate(obj["CreationDate"]) },
                                { "is_involved", involved.Contains(pid).ToString() }
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                rows.Add(ErrorRow("process_tree_error", ex.Message));
            }

            return rows;
        }

        private Dictionary<int, ProcessSnapshot> BuildProcessSnapshots(IEnumerable<Dictionary<string, string>> processRows, IEnumerable<int> involvedPids)
        {
            Dictionary<int, ProcessSnapshot> snapshots = new Dictionary<int, ProcessSnapshot>();
            foreach (Dictionary<string, string> row in processRows)
            {
                int pid;
                if (!TryGetInt(row, "process_id", out pid))
                {
                    continue;
                }

                ProcessSnapshot snapshot = new ProcessSnapshot
                {
                    ProcessId = pid,
                    ParentProcessId = GetInt(row, "parent_process_id"),
                    Name = Get(row, "name"),
                    Path = Get(row, "path"),
                    CommandLine = Get(row, "command_line")
                };

                snapshots[pid] = snapshot;
            }

            foreach (int pid in involvedPids)
            {
                if (!snapshots.ContainsKey(pid))
                {
                    snapshots[pid] = BuildFallbackProcessSnapshot(pid);
                }
            }

            return snapshots;
        }

        private ProcessSnapshot BuildFallbackProcessSnapshot(int processId)
        {
            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    return new ProcessSnapshot
                    {
                        ProcessId = processId,
                        Name = process.ProcessName,
                        Path = TryGetProcessPath(processId)
                    };
                }
            }
            catch
            {
                return new ProcessSnapshot { ProcessId = processId };
            }
        }

        private List<Dictionary<string, string>> CaptureLoadedModules(ICollection<int> involvedPids)
        {
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            foreach (int processId in involvedPids.Distinct())
            {
                try
                {
                    using (Process process = Process.GetProcessById(processId))
                    {
                        foreach (ProcessModule module in process.Modules)
                        {
                            try
                            {
                                SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(module.FileName);
                                Dictionary<string, string> fileDetails = FileClassifier.BuildFileDetails(module.FileName, _options, true);
                                rows.Add(new Dictionary<string, string>
                                {
                                    { "process_id", processId.ToString(CultureInfo.InvariantCulture) },
                                    { "process_name", SafeProcessName(process) },
                                    { "module_name", module.ModuleName ?? string.Empty },
                                    { "module_path", module.FileName ?? string.Empty },
                                    { "base_address", "0x" + module.BaseAddress.ToInt64().ToString("X", CultureInfo.InvariantCulture) },
                                    { "module_memory_size", module.ModuleMemorySize.ToString(CultureInfo.InvariantCulture) },
                                    { "sha256", Get(fileDetails, "sha256") },
                                    { "signature_status", signature.Status ?? string.Empty },
                                    { "signature_subject", signature.Subject ?? string.Empty }
                                });
                            }
                            catch
                            {
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    rows.Add(new Dictionary<string, string>
                    {
                        { "process_id", processId.ToString(CultureInfo.InvariantCulture) },
                        { "error", ex.Message }
                    });
                }
            }

            return rows;
        }

        private MemoryCaptureResult CaptureMemoryMetadata(ICollection<int> involvedPids, IDictionary<int, ProcessSnapshot> processSnapshots)
        {
            MemoryCaptureResult result = new MemoryCaptureResult();
            foreach (int processId in involvedPids.Distinct())
            {
                CaptureProcessMemoryMetadata(processId, processSnapshots, result);
            }

            return result;
        }

        private void CaptureProcessMemoryMetadata(int processId, IDictionary<int, ProcessSnapshot> processSnapshots, MemoryCaptureResult result)
        {
            IntPtr processHandle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION | NativeMethods.PROCESS_VM_READ,
                false,
                processId);

            ProcessSnapshot snapshot = null;
            if (processSnapshots != null)
            {
                processSnapshots.TryGetValue(processId, out snapshot);
            }

            if (processHandle == IntPtr.Zero)
            {
                result.SummaryRows.Add(new Dictionary<string, string>
                {
                    { "process_id", processId.ToString(CultureInfo.InvariantCulture) },
                    { "process_name", snapshot == null ? string.Empty : snapshot.Name ?? string.Empty },
                    { "error", "OpenProcess failed; insufficient access or process exited." }
                });
                return;
            }

            try
            {
                List<ThreadStartInfo> threadStarts = CaptureThreadStarts(processId);
                ulong totalBytes = 0;
                int committedRegions = 0;
                int privateExecutable = 0;
                int rwxPrivate = 0;
                int mappedRegions = 0;
                int imageRegions = 0;
                int suspiciousCaptured = 0;
                ulong address = 0;
                int mbiSize = Marshal.SizeOf(typeof(NativeMethods.MEMORY_BASIC_INFORMATION));

                while (true)
                {
                    NativeMethods.MEMORY_BASIC_INFORMATION info;
                    UIntPtr queryResult = NativeMethods.VirtualQueryEx(
                        processHandle,
                        new IntPtr(unchecked((long)address)),
                        out info,
                        new UIntPtr((uint)mbiSize));

                    if (queryResult == UIntPtr.Zero)
                    {
                        break;
                    }

                    ulong baseAddress = unchecked((ulong)info.BaseAddress.ToInt64());
                    ulong regionSize = info.RegionSize.ToUInt64();
                    ulong nextAddress = baseAddress + regionSize;
                    if (regionSize == 0 || nextAddress <= address)
                    {
                        break;
                    }

                    if (info.State == NativeMethods.MEM_COMMIT)
                    {
                        committedRegions++;
                        totalBytes += regionSize;
                        if (info.Type == NativeMethods.MEM_MAPPED)
                        {
                            mappedRegions++;
                        }
                        else if (info.Type == NativeMethods.MEM_IMAGE)
                        {
                            imageRegions++;
                        }

                        bool executable = IsExecutableProtection(info.Protect);
                        bool rwx = IsRwxProtection(info.Protect);
                        string mappedPath = null;
                        if (info.Type == NativeMethods.MEM_IMAGE || info.Type == NativeMethods.MEM_MAPPED)
                        {
                            mappedPath = TryGetMappedPath(processHandle, info.BaseAddress);
                        }

                        bool suspiciousLocation = !string.IsNullOrWhiteSpace(mappedPath) &&
                                                  (FileClassifier.IsLikelyDownloadLocation(mappedPath) ||
                                                   FileClassifier.IsUnder(mappedPath, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) ||
                                                   FileClassifier.IsUnder(mappedPath, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)));

                        MemorySample sample = ReadMemorySample(processHandle, info.BaseAddress, regionSize);
                        bool hasPeHeader = sample.HasPeHeader;
                        bool suspicious = (info.Type == NativeMethods.MEM_PRIVATE && executable) ||
                                          rwx ||
                                          hasPeHeader ||
                                          suspiciousLocation;

                        if (info.Type == NativeMethods.MEM_PRIVATE && executable)
                        {
                            privateExecutable++;
                        }

                        if (info.Type == NativeMethods.MEM_PRIVATE && rwx)
                        {
                            rwxPrivate++;
                        }

                        if (suspicious && suspiciousCaptured < _options.ActiveCaptureMaxMemoryRegionsPerProcess)
                        {
                            List<ThreadStartInfo> linkedThreads = threadStarts
                                .Where(t => t.StartAddress >= baseAddress && t.StartAddress < baseAddress + regionSize)
                                .ToList();

                            result.SuspiciousRegionRows.Add(new Dictionary<string, string>
                            {
                                { "process_id", processId.ToString(CultureInfo.InvariantCulture) },
                                { "process_name", snapshot == null ? string.Empty : snapshot.Name ?? string.Empty },
                                { "process_path", snapshot == null ? string.Empty : snapshot.Path ?? string.Empty },
                                { "base_address", "0x" + baseAddress.ToString("X", CultureInfo.InvariantCulture) },
                                { "size", regionSize.ToString(CultureInfo.InvariantCulture) },
                                { "protection", DecodeMemoryProtection(info.Protect) },
                                { "protection_raw", "0x" + info.Protect.ToString("X", CultureInfo.InvariantCulture) },
                                { "type", DecodeMemoryType(info.Type) },
                                { "entropy_sample", sample.Entropy.HasValue ? sample.Entropy.Value.ToString("0.000", CultureInfo.InvariantCulture) : string.Empty },
                                { "pe_header_presence", hasPeHeader.ToString() },
                                { "mapped_path", mappedPath ?? string.Empty },
                                { "suspicious_location", suspiciousLocation.ToString() },
                                { "thread_start_links", FormatThreadLinks(linkedThreads) },
                                { "capture_note", "Metadata only; no full process memory dump collected." }
                            });
                            suspiciousCaptured++;
                        }
                    }

                    address = nextAddress;
                }

                result.SummaryRows.Add(new Dictionary<string, string>
                {
                    { "process_id", processId.ToString(CultureInfo.InvariantCulture) },
                    { "process_name", snapshot == null ? string.Empty : snapshot.Name ?? string.Empty },
                    { "process_path", snapshot == null ? string.Empty : snapshot.Path ?? string.Empty },
                    { "committed_region_count", committedRegions.ToString(CultureInfo.InvariantCulture) },
                    { "committed_bytes", totalBytes.ToString(CultureInfo.InvariantCulture) },
                    { "mapped_region_count", mappedRegions.ToString(CultureInfo.InvariantCulture) },
                    { "image_region_count", imageRegions.ToString(CultureInfo.InvariantCulture) },
                    { "private_executable_region_count", privateExecutable.ToString(CultureInfo.InvariantCulture) },
                    { "rwx_private_region_count", rwxPrivate.ToString(CultureInfo.InvariantCulture) },
                    { "suspicious_region_metadata_count", suspiciousCaptured.ToString(CultureInfo.InvariantCulture) }
                });
            }
            finally
            {
                NativeMethods.CloseHandle(processHandle);
            }
        }

        private List<ThreadStartInfo> CaptureThreadStarts(int processId)
        {
            List<ThreadStartInfo> starts = new List<ThreadStartInfo>();
            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    foreach (ProcessThread thread in process.Threads)
                    {
                        try
                        {
                            IntPtr start;
                            if (TryQueryThreadStartAddress(thread.Id, out start) && start != IntPtr.Zero)
                            {
                                starts.Add(new ThreadStartInfo
                                {
                                    ThreadId = thread.Id,
                                    StartAddress = unchecked((ulong)start.ToInt64())
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

            return starts;
        }

        private bool TryQueryThreadStartAddress(int threadId, out IntPtr startAddress)
        {
            startAddress = IntPtr.Zero;
            IntPtr threadHandle = NativeMethods.OpenThread(
                NativeMethods.THREAD_QUERY_INFORMATION | NativeMethods.THREAD_QUERY_LIMITED_INFORMATION,
                false,
                threadId);

            if (threadHandle == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                int status = NativeMethods.NtQueryInformationThread(threadHandle, 9, out startAddress, IntPtr.Size, IntPtr.Zero);
                return status == 0;
            }
            finally
            {
                NativeMethods.CloseHandle(threadHandle);
            }
        }

        private List<Dictionary<string, string>> CaptureOpenHandles(ICollection<int> involvedPids)
        {
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            if (_options.ActiveCaptureMaxHandlesToInspect <= 0 || involvedPids == null || involvedPids.Count == 0)
            {
                return rows;
            }

            HashSet<int> involved = new HashSet<int>(involvedPids);
            Dictionary<int, int> perProcess = new Dictionary<int, int>();
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
                        return rows;
                    }

                    length = Math.Max(length * 2, returnedLength + 1024);
                }

                if (buffer == IntPtr.Zero)
                {
                    return rows;
                }

                long handleCount = Marshal.ReadIntPtr(buffer).ToInt64();
                IntPtr entryPtr = IntPtr.Add(buffer, IntPtr.Size * 2);
                int entrySize = Marshal.SizeOf(typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                int inspected = 0;

                for (long i = 0; i < handleCount && inspected < _options.ActiveCaptureMaxHandlesToInspect; i++)
                {
                    NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry =
                        (NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(entryPtr, typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                    entryPtr = IntPtr.Add(entryPtr, entrySize);
                    inspected++;

                    int processId = unchecked((int)entry.UniqueProcessId.ToUInt64());
                    if (!involved.Contains(processId))
                    {
                        continue;
                    }

                    int count;
                    perProcess.TryGetValue(processId, out count);
                    if (count >= 256)
                    {
                        continue;
                    }

                    Dictionary<string, string> row = TryDescribeHandle(processId, entry);
                    if (row != null)
                    {
                        perProcess[processId] = count + 1;
                        rows.Add(row);
                    }
                }
            }
            catch (Exception ex)
            {
                rows.Add(ErrorRow("handle_snapshot_error", ex.Message));
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return rows;
        }

        private Dictionary<string, string> TryDescribeHandle(int processId, NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry)
        {
            IntPtr sourceProcessHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_DUP_HANDLE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (sourceProcessHandle == IntPtr.Zero)
            {
                return null;
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
                    return null;
                }

                string type = QueryObjectString(duplicatedHandle, NativeMethods.ObjectTypeInformation);
                if (string.IsNullOrWhiteSpace(type))
                {
                    return null;
                }

                string name = QueryObjectString(duplicatedHandle, NativeMethods.ObjectNameInformation);
                int targetPid = 0;
                if (type.Equals("Process", StringComparison.OrdinalIgnoreCase))
                {
                    targetPid = NativeMethods.GetProcessId(duplicatedHandle);
                    if (string.IsNullOrWhiteSpace(name) && targetPid > 0)
                    {
                        name = "Process:" + targetPid.ToString(CultureInfo.InvariantCulture);
                    }
                }

                return new Dictionary<string, string>
                {
                    { "process_id", processId.ToString(CultureInfo.InvariantCulture) },
                    { "process_name", TryGetProcessName(processId) ?? string.Empty },
                    { "handle_value", "0x" + entry.HandleValue.ToUInt64().ToString("X", CultureInfo.InvariantCulture) },
                    { "object_type", type },
                    { "object_name", name ?? string.Empty },
                    { "granted_access", "0x" + entry.GrantedAccess.ToString("X", CultureInfo.InvariantCulture) },
                    { "decoded_access", DecodeHandleAccess(type, entry.GrantedAccess) },
                    { "target_process_id", targetPid > 0 ? targetPid.ToString(CultureInfo.InvariantCulture) : string.Empty }
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

                NativeMethods.CloseHandle(sourceProcessHandle);
            }
        }

        private List<Dictionary<string, string>> CaptureRegistrySnapshots()
        {
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            foreach (RegistryWatchTarget target in BuildRegistryCaptureTargets())
            {
                RegistrySnapshot snapshot = RegistrySnapshot.Capture(target);
                if (!snapshot.IsAvailable)
                {
                    rows.Add(new Dictionary<string, string>
                    {
                        { "key", target.DisplayName },
                        { "available", "False" },
                        { "error", snapshot.Error ?? string.Empty }
                    });
                    continue;
                }

                foreach (string key in snapshot.Keys.Take(500))
                {
                    rows.Add(new Dictionary<string, string>
                    {
                        { "key", key },
                        { "available", "True" },
                        { "record_type", "key" }
                    });
                }

                foreach (KeyValuePair<string, string> value in snapshot.Values.Take(1500))
                {
                    rows.Add(new Dictionary<string, string>
                    {
                        { "key", value.Key },
                        { "available", "True" },
                        { "record_type", "value" },
                        { "value", Truncate(value.Value, 1600) }
                    });
                }
            }

            return rows;
        }

        private IEnumerable<RegistryWatchTarget> BuildRegistryCaptureTargets()
        {
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\CI", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Exclusions", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell", true, 3, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Sysmon", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", true, 2, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true, 1, EventSeverity.High);
            yield return new RegistryWatchTarget(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", true, 1, EventSeverity.High);
        }

        private List<Dictionary<string, string>> PreserveArtifacts(IEnumerable<string> candidatePaths, string filesFolder)
        {
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            foreach (string path in candidatePaths.Where(IsEvidencePath).Distinct(StringComparer.OrdinalIgnoreCase).Take(64))
            {
                Dictionary<string, string> fileDetails = FileClassifier.BuildFileDetails(path, _options, true);
                SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(path);
                Dictionary<string, string> row = new Dictionary<string, string>
                {
                    { "original_path", path },
                    { "exists", File.Exists(path).ToString() },
                    { "sha256", Get(fileDetails, "sha256") },
                    { "signature_status", signature.Status ?? string.Empty },
                    { "signature_subject", signature.Subject ?? string.Empty },
                    { "copied_path", string.Empty },
                    { "copy_error", string.Empty }
                };

                foreach (KeyValuePair<string, string> detail in fileDetails)
                {
                    row["file_" + detail.Key] = detail.Value;
                }

                if (File.Exists(path))
                {
                    try
                    {
                        FileInfo info = new FileInfo(path);
                        if (info.Length <= 250L * 1024L * 1024L)
                        {
                            string hashOrStamp = string.IsNullOrWhiteSpace(Get(fileDetails, "sha256"))
                                ? DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture)
                                : Get(fileDetails, "sha256").Substring(0, Math.Min(16, Get(fileDetails, "sha256").Length));

                            string destination = Path.Combine(filesFolder, hashOrStamp + "-" + SanitizeFileName(Path.GetFileName(path)));
                            File.Copy(path, destination, false);
                            row["copied_path"] = destination;
                        }
                        else
                        {
                            row["copy_error"] = "File exceeds active-capture preservation size limit.";
                        }
                    }
                    catch (Exception ex)
                    {
                        row["copy_error"] = ex.Message;
                    }
                }

                rows.Add(row);
            }

            return rows;
        }

        private List<Dictionary<string, string>> CaptureEventLogExcerpts()
        {
            List<Dictionary<string, string>> rows = new List<Dictionary<string, string>>();
            string[] logs =
            {
                "Security",
                "System",
                "Microsoft-Windows-Sysmon/Operational",
                "Microsoft-Windows-CodeIntegrity/Operational",
                "Microsoft-Windows-PowerShell/Operational"
            };

            int milliseconds = Math.Max(1, _options.ActiveCaptureEventLogMinutes) * 60 * 1000;
            string query = "*[System[TimeCreated[timediff(@SystemTime) <= " + milliseconds.ToString(CultureInfo.InvariantCulture) + "]]]";

            foreach (string log in logs)
            {
                try
                {
                    EventLogQuery eventQuery = new EventLogQuery(log, PathType.LogName, query)
                    {
                        ReverseDirection = true,
                        TolerateQueryErrors = true
                    };

                    using (EventLogReader reader = new EventLogReader(eventQuery))
                    {
                        for (int i = 0; i < 80; i++)
                        {
                            using (EventRecord record = reader.ReadEvent())
                            {
                                if (record == null)
                                {
                                    break;
                                }

                                rows.Add(new Dictionary<string, string>
                                {
                                    { "log_name", log },
                                    { "provider", record.ProviderName ?? string.Empty },
                                    { "event_id", record.Id.ToString(CultureInfo.InvariantCulture) },
                                    { "record_id", record.RecordId.HasValue ? record.RecordId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty },
                                    { "time_created_utc", record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture) : string.Empty },
                                    { "level", record.Level.HasValue ? record.Level.Value.ToString(CultureInfo.InvariantCulture) : string.Empty },
                                    { "description", Truncate(TryFormatDescription(record), 1200) }
                                });
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    rows.Add(new Dictionary<string, string>
                    {
                        { "log_name", log },
                        { "error", ex.Message }
                    });
                }
            }

            return rows;
        }

        private List<Dictionary<string, string>> BuildTimelineRows(IEnumerable<RecentSignal> signals)
        {
            return signals
                .OrderBy(s => s.TimestampUtc)
                .Select(s =>
                {
                    Dictionary<string, string> row = new Dictionary<string, string>
                    {
                        { "timestamp_utc", s.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) },
                        { "category", s.Category ?? string.Empty },
                        { "action", s.Action ?? string.Empty },
                        { "severity", s.Severity.ToString() },
                        { "description", s.Description ?? string.Empty },
                        { "path", s.Path ?? string.Empty },
                        { "process_id", s.ProcessId.HasValue ? s.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty },
                        { "process_name", s.ProcessName ?? string.Empty },
                        { "case_id", s.CaseId ?? string.Empty },
                        { "confidence_score", s.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) }
                    };

                    foreach (KeyValuePair<string, string> detail in s.Details)
                    {
                        row["detail_" + detail.Key] = detail.Value;
                    }

                    return row;
                })
                .ToList();
        }

        private void WriteSummary(string path, CaptureRequest request, IDictionary<int, ProcessSnapshot> processSnapshots, List<Dictionary<string, string>> artifacts, List<Dictionary<string, string>> memoryRegions, List<Dictionary<string, string>> handles)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Active Capture Summary");
            builder.AppendLine("======================");
            builder.AppendLine("CaptureId: " + request.CaptureId);
            builder.AppendLine("Trigger: " + request.TriggerKind);
            builder.AppendLine("Reason: " + request.TriggerReason);
            builder.AppendLine("UpstreamCaseId: " + (request.UpstreamCaseId ?? string.Empty));
            builder.AppendLine("CreatedUtc: " + DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
            builder.AppendLine();
            builder.AppendLine("Chain Summary");
            builder.AppendLine("-------------");
            builder.AppendLine(BuildHumanChainSummary(request, processSnapshots, artifacts, memoryRegions, handles));
            builder.AppendLine();
            builder.AppendLine("Involved Processes");
            builder.AppendLine("------------------");

            foreach (int pid in request.InvolvedProcessIds.Distinct().OrderBy(p => p))
            {
                ProcessSnapshot snapshot;
                processSnapshots.TryGetValue(pid, out snapshot);
                builder.AppendLine(pid.ToString(CultureInfo.InvariantCulture) + " " +
                                   (snapshot == null ? string.Empty : snapshot.Name ?? string.Empty) + " " +
                                   (snapshot == null ? string.Empty : snapshot.Path ?? string.Empty));
            }

            builder.AppendLine();
            builder.AppendLine("Preserved Evidence Files");
            builder.AppendLine("------------------------");
            foreach (Dictionary<string, string> artifact in artifacts)
            {
                builder.AppendLine(Get(artifact, "original_path") + " -> " + Get(artifact, "copied_path") + " [" + Get(artifact, "signature_status") + "]");
            }

            builder.AppendLine();
            builder.AppendLine("Safety");
            builder.AppendLine("------");
            builder.AppendLine("Evidence-only capture. No killing, blocking, driver unloading, memory patching, stealth, injection, or bypass behavior was performed.");

            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }

        private string BuildHumanChainSummary(CaptureRequest request, IDictionary<int, ProcessSnapshot> processSnapshots, List<Dictionary<string, string>> artifacts, List<Dictionary<string, string>> memoryRegions, List<Dictionary<string, string>> handles)
        {
            string sourceName = FirstNonEmpty(
                request.Trigger.Detail("source_process_name"),
                request.Trigger.ProcessName,
                ProcessNameForPid(GetSignalPid(request.Trigger), processSnapshots));

            string sourcePath = FirstNonEmpty(request.Trigger.Detail("source_path"), request.Trigger.Path);
            string targetName = FirstNonEmpty(request.Trigger.Detail("target_process_name"), FindProtectedTargetName(processSnapshots));
            string access = FirstNonEmpty(request.Trigger.Detail("decoded_access"), request.Trigger.Detail("granted_access"), request.Trigger.Detail("access_rights"));
            string device = FirstNonEmpty(request.Trigger.Detail("object_name"), FirstHandleObject(handles, "Device"));
            string artifact = FirstArtifactPath(artifacts);
            bool privateMemory = memoryRegions.Any(r => Get(r, "type").Equals("MEM_PRIVATE", StringComparison.OrdinalIgnoreCase) &&
                                                        Get(r, "protection").IndexOf("EXECUTE", StringComparison.OrdinalIgnoreCase) >= 0);

            List<string> parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(sourceName))
            {
                string location = FriendlyLocation(sourcePath);
                parts.Add((IsUnsignedSource(request.Trigger) ? "Unsigned loader " : "Process ") + sourceName +
                          (string.IsNullOrWhiteSpace(location) ? string.Empty : " launched from " + location));
            }

            if (!string.IsNullOrWhiteSpace(artifact))
            {
                parts.Add("created or referenced artifact " + artifact);
            }

            if (!string.IsNullOrWhiteSpace(device))
            {
                parts.Add("opened communication object " + device);
            }

            if (!string.IsNullOrWhiteSpace(targetName))
            {
                parts.Add("accessed " + targetName + (string.IsNullOrWhiteSpace(access) ? string.Empty : " with " + access));
            }

            if (privateMemory)
            {
                parts.Add(targetName + " later showed private executable memory metadata");
            }

            if (parts.Count == 0)
            {
                return request.Trigger.Description;
            }

            return string.Join(", then ", parts.ToArray()) + ".";
        }

        private List<RecentSignal> CollectRelatedSignals(RecentSignal trigger)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            string caseId = trigger.CaseId ?? trigger.Detail("case_id");
            HashSet<int> triggerPids = new HashSet<int>();
            AddSignalProcessIds(trigger, triggerPids);
            HashSet<string> triggerPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            AddSignalPaths(trigger, triggerPaths);

            List<RecentSignal> related = _recentSignals
                .Where(s => s.TimestampUtc >= cutoff && IsRelatedSignal(s, trigger, caseId, triggerPids, triggerPaths))
                .OrderBy(s => s.TimestampUtc)
                .Take(200)
                .ToList();

            if (!related.Contains(trigger))
            {
                related.Add(trigger);
            }

            return related.OrderBy(s => s.TimestampUtc).ToList();
        }

        private bool IsRelatedSignal(RecentSignal signal, RecentSignal trigger, string caseId, ISet<int> triggerPids, ISet<string> triggerPaths)
        {
            if (!string.IsNullOrWhiteSpace(caseId) && string.Equals(signal.CaseId, caseId, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            HashSet<int> signalPids = new HashSet<int>();
            AddSignalProcessIds(signal, signalPids);
            if (signalPids.Any(p => triggerPids.Contains(p)))
            {
                return true;
            }

            HashSet<string> signalPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            AddSignalPaths(signal, signalPaths);
            if (signalPaths.Any(p => triggerPaths.Contains(p)))
            {
                return true;
            }

            return IsRelevant(signal) && (signal.Severity >= EventSeverity.High || signal.Category.Equals(trigger.Category, StringComparison.OrdinalIgnoreCase));
        }

        private void AddSignalProcessIds(RecentSignal signal, ISet<int> pids)
        {
            if (signal.ProcessId.HasValue && signal.ProcessId.Value > 0)
            {
                pids.Add(signal.ProcessId.Value);
            }

            AddPid(signal.Detail("source_process_id"), pids);
            AddPid(signal.Detail("target_process_id"), pids);
            AddPid(signal.Detail("process_id"), pids);
            AddPid(signal.Detail("pid"), pids);
        }

        private void AddSignalPaths(RecentSignal signal, ISet<string> paths)
        {
            AddPath(signal.Path, paths);
            foreach (KeyValuePair<string, string> detail in signal.Details)
            {
                string key = detail.Key ?? string.Empty;
                if (key.IndexOf("path", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    key.IndexOf("file", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    key.IndexOf("image", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    key.IndexOf("module", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    ExtractPaths(detail.Value, paths);
                }
            }
        }

        private void AddProtectedTargetPids(ISet<int> pids)
        {
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    string name = process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                        ? process.ProcessName
                        : process.ProcessName + ".exe";
                    string path = TryGetProcessPath(process.Id);
                    if (TargetProcessMatcher.IsProtectedProcessName(name, _options.ProtectedProcessNames) ||
                        TargetProcessMatcher.IsProtectedProcessName(path, _options.ProtectedProcessNames))
                    {
                        pids.Add(process.Id);
                    }
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        private bool HasRecent(Func<RecentSignal, bool> predicate, TimeSpan window)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(window);
            return _recentSignals.Any(s => s.TimestampUtc >= cutoff && predicate(s));
        }

        private bool IsRelevant(RecentSignal signal)
        {
            string text = signal.Text;
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            return ContainsAny(
                text,
                "driver", ".sys", ".dll", ".exe", "loader", "mapper", "device", "section",
                "namedpipe", "alpc", "target", "game", "privateexecutable", "rwx", "unsigned",
                "untrusted", "mapped", "service", "codeintegrity", "shortlived", "downloaded");
        }

        private void CleanupRecentSignals()
        {
            lock (_cleanupLock)
            {
                DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
                while (_recentSignals.TryPeek(out RecentSignal signal) && signal.TimestampUtc < cutoff)
                {
                    RecentSignal ignored;
                    _recentSignals.TryDequeue(out ignored);
                }

                foreach (KeyValuePair<string, DateTime> pair in _captureTimesByKey.ToArray())
                {
                    if (pair.Value < DateTime.UtcNow.Subtract(TimeSpan.FromHours(1)))
                    {
                        DateTime ignored;
                        _captureTimesByKey.TryRemove(pair.Key, out ignored);
                    }
                }
            }
        }

        private string BuildCaptureKey(RecentSignal signal, TriggerDecision decision)
        {
            string caseId = signal.CaseId ?? signal.Detail("case_id");
            if (!string.IsNullOrWhiteSpace(caseId))
            {
                return decision.Kind + "|" + caseId;
            }

            return decision.Kind + "|" +
                   (signal.ProcessId.HasValue ? signal.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : "nopid") + "|" +
                   (signal.Path ?? signal.Detail("target_process_id") ?? signal.Detail("source_process_id") ?? signal.Action ?? "unknown");
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

        private MemorySample ReadMemorySample(IntPtr processHandle, IntPtr baseAddress, ulong regionSize)
        {
            int size = (int)Math.Min(4096UL, regionSize);
            if (size <= 0)
            {
                return new MemorySample();
            }

            byte[] buffer = new byte[size];
            IntPtr bytesRead;
            if (!NativeMethods.ReadProcessMemory(processHandle, baseAddress, buffer, buffer.Length, out bytesRead) || bytesRead.ToInt64() <= 0)
            {
                return new MemorySample();
            }

            int read = (int)Math.Min(bytesRead.ToInt64(), buffer.Length);
            return new MemorySample
            {
                Entropy = CalculateEntropy(buffer, read),
                HasPeHeader = LooksLikePeHeader(buffer, read)
            };
        }

        private static double CalculateEntropy(byte[] buffer, int length)
        {
            if (buffer == null || length <= 0)
            {
                return 0;
            }

            int[] counts = new int[256];
            for (int i = 0; i < length; i++)
            {
                counts[buffer[i]]++;
            }

            double entropy = 0;
            for (int i = 0; i < counts.Length; i++)
            {
                if (counts[i] == 0)
                {
                    continue;
                }

                double p = (double)counts[i] / length;
                entropy -= p * (Math.Log(p) / Math.Log(2));
            }

            return entropy;
        }

        private static bool LooksLikePeHeader(byte[] buffer, int length)
        {
            if (buffer == null || length < 0x100 || buffer[0] != (byte)'M' || buffer[1] != (byte)'Z')
            {
                return false;
            }

            int peOffset = BitConverter.ToInt32(buffer, 0x3C);
            return peOffset > 0 && peOffset + 4 < length &&
                   buffer[peOffset] == (byte)'P' &&
                   buffer[peOffset + 1] == (byte)'E' &&
                   buffer[peOffset + 2] == 0 &&
                   buffer[peOffset + 3] == 0;
        }

        private string TryGetMappedPath(IntPtr processHandle, IntPtr baseAddress)
        {
            try
            {
                StringBuilder builder = new StringBuilder(4096);
                int length = NativeMethods.GetMappedFileName(processHandle, baseAddress, builder, builder.Capacity);
                if (length <= 0)
                {
                    return null;
                }

                return new DevicePathResolver().ToDosPath(builder.ToString());
            }
            catch
            {
                return null;
            }
        }

        private static bool IsExecutableProtection(uint protect)
        {
            uint clean = protect & ~NativeMethods.PAGE_GUARD;
            return clean == NativeMethods.PAGE_EXECUTE ||
                   clean == NativeMethods.PAGE_EXECUTE_READ ||
                   clean == NativeMethods.PAGE_EXECUTE_READWRITE ||
                   clean == NativeMethods.PAGE_EXECUTE_WRITECOPY;
        }

        private static bool IsRwxProtection(uint protect)
        {
            uint clean = protect & ~NativeMethods.PAGE_GUARD;
            return clean == NativeMethods.PAGE_EXECUTE_READWRITE ||
                   clean == NativeMethods.PAGE_EXECUTE_WRITECOPY;
        }

        private static string DecodeMemoryProtection(uint protect)
        {
            uint clean = protect & ~NativeMethods.PAGE_GUARD;
            string name;
            switch (clean)
            {
                case NativeMethods.PAGE_NOACCESS:
                    name = "NOACCESS";
                    break;
                case NativeMethods.PAGE_READONLY:
                    name = "READONLY";
                    break;
                case NativeMethods.PAGE_READWRITE:
                    name = "READWRITE";
                    break;
                case NativeMethods.PAGE_WRITECOPY:
                    name = "WRITECOPY";
                    break;
                case NativeMethods.PAGE_EXECUTE:
                    name = "EXECUTE";
                    break;
                case NativeMethods.PAGE_EXECUTE_READ:
                    name = "EXECUTE_READ";
                    break;
                case NativeMethods.PAGE_EXECUTE_READWRITE:
                    name = "EXECUTE_READWRITE";
                    break;
                case NativeMethods.PAGE_EXECUTE_WRITECOPY:
                    name = "EXECUTE_WRITECOPY";
                    break;
                default:
                    name = "0x" + clean.ToString("X", CultureInfo.InvariantCulture);
                    break;
            }

            if ((protect & NativeMethods.PAGE_GUARD) != 0)
            {
                name += "|GUARD";
            }

            return name;
        }

        private static string DecodeMemoryType(uint type)
        {
            if (type == NativeMethods.MEM_PRIVATE) return "MEM_PRIVATE";
            if (type == NativeMethods.MEM_IMAGE) return "MEM_IMAGE";
            if (type == NativeMethods.MEM_MAPPED) return "MEM_MAPPED";
            return "0x" + type.ToString("X", CultureInfo.InvariantCulture);
        }

        private static string DecodeHandleAccess(string type, uint access)
        {
            if (type.Equals("Process", StringComparison.OrdinalIgnoreCase))
            {
                List<string> rights = new List<string>();
                AddRight(rights, access, NativeMethods.PROCESS_VM_READ, "PROCESS_VM_READ");
                AddRight(rights, access, NativeMethods.PROCESS_VM_WRITE, "PROCESS_VM_WRITE");
                AddRight(rights, access, NativeMethods.PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION");
                AddRight(rights, access, NativeMethods.PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD");
                AddRight(rights, access, NativeMethods.PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE");
                AddRight(rights, access, NativeMethods.PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION");
                AddRight(rights, access, NativeMethods.PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME");
                return rights.Count == 0 ? "0x" + access.ToString("X", CultureInfo.InvariantCulture) : string.Join("|", rights.ToArray());
            }

            if (type.Equals("Section", StringComparison.OrdinalIgnoreCase))
            {
                List<string> rights = new List<string>();
                AddRight(rights, access, NativeMethods.SECTION_QUERY, "SECTION_QUERY");
                AddRight(rights, access, NativeMethods.SECTION_MAP_READ, "SECTION_MAP_READ");
                AddRight(rights, access, NativeMethods.SECTION_MAP_WRITE, "SECTION_MAP_WRITE");
                AddRight(rights, access, NativeMethods.SECTION_MAP_EXECUTE, "SECTION_MAP_EXECUTE");
                AddRight(rights, access, NativeMethods.SECTION_EXTEND_SIZE, "SECTION_EXTEND_SIZE");
                return rights.Count == 0 ? "0x" + access.ToString("X", CultureInfo.InvariantCulture) : string.Join("|", rights.ToArray());
            }

            return "0x" + access.ToString("X", CultureInfo.InvariantCulture);
        }

        private static void AddRight(ICollection<string> rights, uint access, uint mask, string name)
        {
            if ((access & mask) == mask)
            {
                rights.Add(name);
            }
        }

        private static void WriteJsonArray(string path, IEnumerable<Dictionary<string, string>> rows)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("[");
            bool firstRow = true;
            foreach (Dictionary<string, string> row in rows)
            {
                if (!firstRow)
                {
                    builder.Append(",");
                }

                builder.Append("{");
                bool firstProperty = true;
                foreach (KeyValuePair<string, string> pair in row)
                {
                    JsonUtilities.AppendStringProperty(builder, pair.Key, pair.Value, ref firstProperty);
                }

                builder.Append("}");
                firstRow = false;
            }

            builder.Append("]");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }

        private static void ExtractPaths(string value, ISet<string> paths)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            foreach (string token in value.Split(new[] { '|', ';', '\r', '\n', '\t', '"' }, StringSplitOptions.RemoveEmptyEntries))
            {
                AddPath(token.Trim(), paths);
            }

            AddPath(value.Trim(), paths);
        }

        private static void AddPath(string value, ISet<string> paths)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            string trimmed = value.Trim().Trim('\'', '"');
            if (IsEvidencePath(trimmed))
            {
                paths.Add(trimmed);
            }
        }

        private static bool IsEvidencePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string extension = Path.GetExtension(path);
            if (!EvidenceExtensions.Contains(extension))
            {
                return false;
            }

            return path.IndexOf(@":\", StringComparison.OrdinalIgnoreCase) > 0 ||
                   path.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExecutableEvidencePath(string path)
        {
            if (!IsEvidencePath(path))
            {
                return false;
            }

            string extension = Path.GetExtension(path);
            return FileClassifier.IsLikelyExecutable(path) ||
                   extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                   extension.Equals(".sys", StringComparison.OrdinalIgnoreCase);
        }

        private static string TryFormatDescription(EventRecord record)
        {
            try
            {
                return record.FormatDescription() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string FormatThreadLinks(IEnumerable<ThreadStartInfo> starts)
        {
            return string.Join("|", starts.Select(s => s.ThreadId.ToString(CultureInfo.InvariantCulture) + "@0x" + s.StartAddress.ToString("X", CultureInfo.InvariantCulture)).ToArray());
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

        private static string SafeProcessName(Process process)
        {
            try
            {
                return process.ProcessName;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static int SafeInt(object value)
        {
            try
            {
                return Convert.ToInt32(value, CultureInfo.InvariantCulture);
            }
            catch
            {
                return 0;
            }
        }

        private static string ConvertWmiDate(object value)
        {
            try
            {
                string text = Convert.ToString(value, CultureInfo.InvariantCulture);
                return string.IsNullOrWhiteSpace(text)
                    ? string.Empty
                    : ManagementDateTimeConverter.ToDateTime(text).ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static bool TryGetInt(Dictionary<string, string> row, string key, out int value)
        {
            value = 0;
            string text;
            return row.TryGetValue(key, out text) && int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        private static int GetInt(Dictionary<string, string> row, string key)
        {
            int value;
            return TryGetInt(row, key, out value) ? value : 0;
        }

        private static string Get(Dictionary<string, string> row, string key)
        {
            if (row == null)
            {
                return string.Empty;
            }

            string value;
            return row.TryGetValue(key, out value) ? value ?? string.Empty : string.Empty;
        }

        private static void AddPid(string value, ISet<int> pids)
        {
            int pid;
            if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out pid) && pid > 0)
            {
                pids.Add(pid);
            }
        }

        private static int GetSignalPid(RecentSignal signal)
        {
            if (signal.ProcessId.HasValue)
            {
                return signal.ProcessId.Value;
            }

            int pid;
            if (int.TryParse(signal.Detail("source_process_id"), NumberStyles.Integer, CultureInfo.InvariantCulture, out pid))
            {
                return pid;
            }

            return 0;
        }

        private static string ProcessNameForPid(int processId, IDictionary<int, ProcessSnapshot> processSnapshots)
        {
            ProcessSnapshot snapshot;
            return processSnapshots != null && processSnapshots.TryGetValue(processId, out snapshot)
                ? snapshot.Name
                : string.Empty;
        }

        private string FindProtectedTargetName(IDictionary<int, ProcessSnapshot> processSnapshots)
        {
            if (processSnapshots == null)
            {
                return string.Empty;
            }

            foreach (ProcessSnapshot snapshot in processSnapshots.Values)
            {
                if (TargetProcessMatcher.IsProtectedProcessName(snapshot.Name, _options.ProtectedProcessNames) ||
                    TargetProcessMatcher.IsProtectedProcessName(snapshot.Path, _options.ProtectedProcessNames))
                {
                    return snapshot.Name;
                }
            }

            return string.Empty;
        }

        private static string FirstArtifactPath(IEnumerable<Dictionary<string, string>> artifacts)
        {
            foreach (Dictionary<string, string> artifact in artifacts)
            {
                string path = Get(artifact, "original_path");
                if (!string.IsNullOrWhiteSpace(path))
                {
                    return Path.GetFileName(path);
                }
            }

            return string.Empty;
        }

        private static string FirstHandleObject(IEnumerable<Dictionary<string, string>> handles, string type)
        {
            foreach (Dictionary<string, string> handle in handles)
            {
                if (Get(handle, "object_type").IndexOf(type, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return Get(handle, "object_name");
                }
            }

            return string.Empty;
        }

        private static bool IsUnsignedSource(RecentSignal signal)
        {
            string status = signal.Detail("source_signature_status");
            return string.IsNullOrWhiteSpace(status) ||
                   status.IndexOf("Trusted", StringComparison.OrdinalIgnoreCase) < 0;
        }

        private static string FriendlyLocation(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (FileClassifier.IsUnder(path, Path.Combine(user, "Downloads")))
            {
                return "Downloads";
            }

            if (FileClassifier.IsUnder(path, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)))
            {
                return "Desktop";
            }

            if (FileClassifier.IsUnder(path, Path.GetTempPath()))
            {
                return "Temp";
            }

            return Path.GetDirectoryName(path) ?? path;
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return string.Empty;
        }

        private static bool ContainsAny(string value, params string[] terms)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            foreach (string term in terms)
            {
                if (value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string Truncate(string value, int max)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= max)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, max) + "...";
        }

        private static Dictionary<string, string> ErrorRow(string type, string message)
        {
            return new Dictionary<string, string>
            {
                { "record_type", type },
                { "error", message ?? string.Empty }
            };
        }

        private static string SanitizeFileName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "unknown";
            }

            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder builder = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                builder.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            }

            return builder.ToString();
        }

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
        }

        private sealed class TriggerDecision
        {
            public TriggerDecision(string reason, string kind)
            {
                Reason = reason;
                Kind = kind;
            }

            public string Reason { get; private set; }

            public string Kind { get; private set; }
        }

        private sealed class CaptureRequest
        {
            public string CaptureKey { get; set; }

            public string CaptureId { get; set; }

            public string TriggerReason { get; set; }

            public string TriggerKind { get; set; }

            public string UpstreamCaseId { get; set; }

            public RecentSignal Trigger { get; set; }

            public List<RecentSignal> RelatedSignals { get; set; }

            public List<int> InvolvedProcessIds { get; set; }

            public List<string> CandidatePaths { get; set; }
        }

        private sealed class RecentSignal
        {
            public DateTime TimestampUtc { get; set; }

            public string Category { get; set; }

            public string Action { get; set; }

            public EventSeverity Severity { get; set; }

            public string Description { get; set; }

            public string Path { get; set; }

            public int? ProcessId { get; set; }

            public string ProcessName { get; set; }

            public string CaseId { get; set; }

            public double ConfidenceScore { get; set; }

            public Dictionary<string, string> Details { get; set; }

            public string Text
            {
                get { return (Category + " " + Action + " " + Description + " " + Path + " " + string.Join(" ", Details.Values.ToArray())).ToLowerInvariant(); }
            }

            public string Detail(string key)
            {
                string value;
                return Details != null && Details.TryGetValue(key, out value) ? value ?? string.Empty : string.Empty;
            }

            public static RecentSignal FromEvent(DetectionEvent detectionEvent)
            {
                Dictionary<string, string> details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (KeyValuePair<string, string> pair in detectionEvent.Details)
                {
                    details[pair.Key] = pair.Value;
                }

                double confidence = 0;
                string confidenceText;
                if (details.TryGetValue("confidence_score", out confidenceText))
                {
                    double.TryParse(confidenceText, NumberStyles.Float, CultureInfo.InvariantCulture, out confidence);
                }

                string caseId;
                details.TryGetValue("case_id", out caseId);

                return new RecentSignal
                {
                    TimestampUtc = detectionEvent.TimestampUtc.UtcDateTime,
                    Category = detectionEvent.Category,
                    Action = detectionEvent.Action,
                    Severity = detectionEvent.Severity,
                    Description = detectionEvent.Description,
                    Path = detectionEvent.Path,
                    ProcessId = detectionEvent.ProcessId,
                    ProcessName = detectionEvent.ProcessName,
                    CaseId = caseId,
                    ConfidenceScore = confidence,
                    Details = details
                };
            }
        }

        private sealed class ProcessSnapshot
        {
            public int ProcessId { get; set; }

            public int ParentProcessId { get; set; }

            public string Name { get; set; }

            public string Path { get; set; }

            public string CommandLine { get; set; }
        }

        private sealed class MemoryCaptureResult
        {
            public MemoryCaptureResult()
            {
                SummaryRows = new List<Dictionary<string, string>>();
                SuspiciousRegionRows = new List<Dictionary<string, string>>();
            }

            public List<Dictionary<string, string>> SummaryRows { get; private set; }

            public List<Dictionary<string, string>> SuspiciousRegionRows { get; private set; }
        }

        private sealed class MemorySample
        {
            public double? Entropy { get; set; }

            public bool HasPeHeader { get; set; }
        }

        private sealed class ThreadStartInfo
        {
            public int ThreadId { get; set; }

            public ulong StartAddress { get; set; }
        }
    }
}
