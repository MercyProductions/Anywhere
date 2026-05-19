using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class TargetProcessInteractionMonitor : IDetectionMonitor
    {
        private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
        private static readonly TimeSpan RelatedEvidenceWindow = TimeSpan.FromMinutes(10);

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private readonly ConcurrentQueue<RelatedSignal> _recentSignals = new ConcurrentQueue<RelatedSignal>();
        private readonly ConcurrentDictionary<int, DateTime> _recentDeviceHandleByProcess = new ConcurrentDictionary<int, DateTime>();
        private readonly ConcurrentDictionary<string, TargetCase> _activeCases = new ConcurrentDictionary<string, TargetCase>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedHandleKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedMemoryKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _reportLock = new object();
        private readonly string _caseRoot;
        private Thread _thread;
        private bool _disposed;

        public TargetProcessInteractionMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _caseRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Target Interaction Cases");
        }

        public string Name
        {
            get { return "Target Process Interaction"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_caseRoot);
            _logger.EventLogged += OnEventLogged;

            _thread = new Thread(ThreadMain)
            {
                IsBackground = true,
                Name = "Aegis Target Process Interaction Monitor"
            };
            _thread.Start();

            _logger.Log(DetectionEvent.Create(
                "TargetInteraction",
                "Started",
                EventSeverity.Low,
                "Target process interaction monitor started.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "protected_targets", string.Join(";", _options.ProtectedProcessNames.ToArray()) },
                    { "target_scan_interval_seconds", _options.TargetInteractionScanInterval.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "max_process_handles", _options.MaxProcessHandlesToInspect.ToString(CultureInfo.InvariantCulture) },
                    { "case_root", _caseRoot }
                }));
        }

        private void ThreadMain()
        {
            while (!_stopSignal.Wait(_options.TargetInteractionScanInterval))
            {
                try
                {
                    List<Process> targets = FindProtectedTargets();
                    if (targets.Count == 0)
                    {
                        continue;
                    }

                    Dictionary<int, TargetProcessInfo> targetMap = targets.ToDictionary(t => t.Id, BuildTargetProcessInfo);
                    ScanProcessHandles(targetMap);

                    foreach (TargetProcessInfo target in targetMap.Values)
                    {
                        ScanTargetMemoryAndThreads(target);
                    }

                    foreach (Process process in targets)
                    {
                        process.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogException("TargetInteraction", "ScanFailed", ex, null);
                }

                CleanupRecentSignals();
            }
        }

        private List<Process> FindProtectedTargets()
        {
            List<Process> targets = new List<Process>();
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    string name = process.ProcessName;
                    string fileName = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name : name + ".exe";
                    string path = TryGetProcessPath(process.Id);

                    if (TargetProcessMatcher.IsProtectedProcessName(fileName, _options.ProtectedProcessNames) ||
                        TargetProcessMatcher.IsProtectedProcessName(path, _options.ProtectedProcessNames))
                    {
                        targets.Add(process);
                    }
                    else
                    {
                        process.Dispose();
                    }
                }
                catch
                {
                    process.Dispose();
                }
            }

            return targets;
        }

        private TargetProcessInfo BuildTargetProcessInfo(Process process)
        {
            return new TargetProcessInfo
            {
                ProcessId = process.Id,
                ProcessName = SafeProcessName(process),
                Path = TryGetProcessPath(process.Id)
            };
        }

        private void ScanProcessHandles(IDictionary<int, TargetProcessInfo> targets)
        {
            if (_options.MaxProcessHandlesToInspect <= 0)
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
                    status = NativeMethods.NtQuerySystemInformation(
                        NativeMethods.SystemExtendedHandleInformation,
                        buffer,
                        length,
                        out returnedLength);

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

                for (long i = 0; i < handleCount && inspected < _options.MaxProcessHandlesToInspect; i++)
                {
                    NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry =
                        (NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(
                            entryPtr,
                            typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

                    entryPtr = IntPtr.Add(entryPtr, entrySize);
                    inspected++;

                    int sourcePid = unchecked((int)entry.UniqueProcessId.ToUInt64());
                    if (sourcePid <= 4 || targets.ContainsKey(sourcePid))
                    {
                        continue;
                    }

                    uint suspiciousAccess = entry.GrantedAccess & SuspiciousProcessAccessMask();
                    if (suspiciousAccess == 0)
                    {
                        continue;
                    }

                    int targetPid = TryResolveProcessHandleTargetPid(sourcePid, entry);
                    TargetProcessInfo target;
                    if (!targets.TryGetValue(targetPid, out target))
                    {
                        continue;
                    }

                    LogSuspiciousProcessHandle(sourcePid, target, entry.GrantedAccess);
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

        private int TryResolveProcessHandleTargetPid(int sourcePid, NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry)
        {
            IntPtr sourceProcessHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_DUP_HANDLE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, sourcePid);
            if (sourceProcessHandle == IntPtr.Zero)
            {
                return 0;
            }

            IntPtr duplicatedHandle = IntPtr.Zero;
            try
            {
                bool duplicated = NativeMethods.DuplicateHandle(
                    sourceProcessHandle,
                    new IntPtr(unchecked((long)entry.HandleValue.ToUInt64())),
                    NativeMethods.GetCurrentProcess(),
                    out duplicatedHandle,
                    0,
                    false,
                    NativeMethods.DUPLICATE_SAME_ACCESS);

                if (!duplicated || duplicatedHandle == IntPtr.Zero)
                {
                    return 0;
                }

                return NativeMethods.GetProcessId(duplicatedHandle);
            }
            catch
            {
                return 0;
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

        private void LogSuspiciousProcessHandle(int sourcePid, TargetProcessInfo target, uint grantedAccess)
        {
            string key = sourcePid.ToString(CultureInfo.InvariantCulture) + "|" +
                         target.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" +
                         grantedAccess.ToString("X", CultureInfo.InvariantCulture);

            lock (_reportedHandleKeys)
            {
                if (!_reportedHandleKeys.Add(key))
                {
                    return;
                }
            }

            ProcessInfo source = BuildProcessInfo(sourcePid);
            ProcessInfo targetProcess = BuildProcessInfo(target.ProcessId);
            SignatureVerificationResult sourceSignature = AuthenticodeVerifier.VerifyFile(source.Path);
            SignatureVerificationResult targetSignature = AuthenticodeVerifier.VerifyFile(targetProcess.Path);
            string caseId = GetOrCreateCaseId(sourcePid, target.ProcessId, "TargetHandle");
            string caseFolder = GetCaseFolder(caseId);

            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "case_id", caseId },
                { "evidence_folder_path", caseFolder },
                { "source_process_id", sourcePid.ToString(CultureInfo.InvariantCulture) },
                { "source_process_name", source.Name ?? string.Empty },
                { "source_path", source.Path ?? string.Empty },
                { "source_sha256", TryHashFile(source.Path) ?? string.Empty },
                { "source_signature_status", sourceSignature.Status ?? string.Empty },
                { "source_signature_subject", sourceSignature.Subject ?? string.Empty },
                { "target_process_id", target.ProcessId.ToString(CultureInfo.InvariantCulture) },
                { "target_process_name", target.ProcessName ?? string.Empty },
                { "target_path", targetProcess.Path ?? target.Path ?? string.Empty },
                { "target_sha256", TryHashFile(targetProcess.Path ?? target.Path) ?? string.Empty },
                { "target_signature_status", targetSignature.Status ?? string.Empty },
                { "target_signature_subject", targetSignature.Subject ?? string.Empty },
                { "granted_access", "0x" + grantedAccess.ToString("X", CultureInfo.InvariantCulture) },
                { "decoded_access", DecodeProcessAccess(grantedAccess) },
                { "parent_process_chain", BuildParentProcessChain(sourcePid) },
                { "related_recent_evidence", SummarizeRelatedSignals(sourcePid, target.ProcessId) },
                { "source_comm_objects", CollectSourceCommunicationObjects(sourcePid) },
                { "visibility", "Visible user-mode handle enumeration; protected or kernel-hidden paths may be unavailable." }
            };

            EventSeverity severity = ClassifyHandleSeverity(grantedAccess, sourceSignature, sourcePid);
            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "TargetInteraction",
                "SuspiciousTargetHandle",
                severity,
                "Process opened suspicious handle to protected target: " + source.Name + " -> " + target.ProcessName,
                target.Path,
                sourcePid,
                source.Name,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
        }

        private EventSeverity ClassifyHandleSeverity(uint grantedAccess, SignatureVerificationResult sourceSignature, int sourcePid)
        {
            bool writesMemory = HasAccess(grantedAccess, NativeMethods.PROCESS_VM_WRITE) ||
                                HasAccess(grantedAccess, NativeMethods.PROCESS_VM_OPERATION) ||
                                HasAccess(grantedAccess, NativeMethods.PROCESS_CREATE_THREAD);
            bool untrustedSource = sourceSignature == null || !sourceSignature.IsTrusted;

            if (writesMemory && untrustedSource)
            {
                return EventSeverity.Critical;
            }

            DateTime deviceSeenAt;
            if (writesMemory && _recentDeviceHandleByProcess.TryGetValue(sourcePid, out deviceSeenAt) &&
                DateTime.UtcNow.Subtract(deviceSeenAt) <= RelatedEvidenceWindow)
            {
                return EventSeverity.Critical;
            }

            if (writesMemory)
            {
                return EventSeverity.High;
            }

            return EventSeverity.Medium;
        }

        private void ScanTargetMemoryAndThreads(TargetProcessInfo target)
        {
            IntPtr processHandle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION | NativeMethods.PROCESS_VM_READ,
                false,
                target.ProcessId);

            if (processHandle == IntPtr.Zero)
            {
                return;
            }

            try
            {
                List<MemoryRegionInfo> mappedRegions = new List<MemoryRegionInfo>();
                List<string> processModulePaths = GetProcessModulePaths(target.ProcessId);
                ulong address = 0;
                int mbiSize = Marshal.SizeOf(typeof(NativeMethods.MEMORY_BASIC_INFORMATION));

                while (true)
                {
                    NativeMethods.MEMORY_BASIC_INFORMATION info;
                    UIntPtr result = NativeMethods.VirtualQueryEx(
                        processHandle,
                        new IntPtr(unchecked((long)address)),
                        out info,
                        new UIntPtr((uint)mbiSize));

                    if (result == UIntPtr.Zero)
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
                        bool executable = IsExecutableProtection(info.Protect);
                        bool rwx = IsRwxProtection(info.Protect);

                        if ((info.Type == NativeMethods.MEM_IMAGE || info.Type == NativeMethods.MEM_MAPPED))
                        {
                            string mappedPath = TryGetMappedPath(processHandle, info.BaseAddress);
                            if (!string.IsNullOrWhiteSpace(mappedPath))
                            {
                                MemoryRegionInfo mapped = new MemoryRegionInfo
                                {
                                    BaseAddress = baseAddress,
                                    Size = regionSize,
                                    Protection = info.Protect,
                                    Type = info.Type,
                                    Path = mappedPath
                                };
                                mappedRegions.Add(mapped);

                                EvaluateMappedImage(target, mapped, processModulePaths);
                            }
                        }
                        else if (info.Type == NativeMethods.MEM_PRIVATE && executable)
                        {
                            bool hasPeHeader = LooksLikePeHeader(processHandle, info.BaseAddress);
                            LogTargetMemoryAnomaly(target, "PrivateExecutableMemory", rwx || hasPeHeader ? EventSeverity.Critical : EventSeverity.High, info, hasPeHeader);
                            if (rwx)
                            {
                                LogTargetMemoryAnomaly(target, "RwxPrivateMemory", EventSeverity.Critical, info, hasPeHeader);
                            }
                            if (hasPeHeader)
                            {
                                LogTargetMemoryAnomaly(target, "PrivatePeHeader", EventSeverity.Critical, info, true);
                            }
                        }
                    }

                    address = nextAddress;
                }

                ScanThreadStartAddresses(target, mappedRegions);
            }
            finally
            {
                NativeMethods.CloseHandle(processHandle);
            }
        }

        private void EvaluateMappedImage(TargetProcessInfo target, MemoryRegionInfo mapped, ICollection<string> processModulePaths)
        {
            string extension = Path.GetExtension(mapped.Path);
            if (!extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
                !extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                !extension.Equals(".sys", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(mapped.Path);
            bool suspiciousLocation = FileClassifier.IsLikelyDownloadLocation(mapped.Path) ||
                                      FileClassifier.IsUnder(mapped.Path, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) ||
                                      FileClassifier.IsUnder(mapped.Path, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));

            if (!signature.IsTrusted || suspiciousLocation)
            {
                Dictionary<string, string> details = BuildTargetBaseDetails(target, null);
                details["case_id"] = GetOrCreateCaseId(0, target.ProcessId, "MappedImage");
                details["mapped_path"] = mapped.Path;
                details["mapped_base"] = "0x" + mapped.BaseAddress.ToString("X", CultureInfo.InvariantCulture);
                details["mapped_size"] = mapped.Size.ToString(CultureInfo.InvariantCulture);
                details["protection"] = "0x" + mapped.Protection.ToString("X", CultureInfo.InvariantCulture);
                details["signature_status"] = signature.Status ?? string.Empty;
                details["signature_subject"] = signature.Subject ?? string.Empty;
                details["suspicious_location"] = suspiciousLocation.ToString();
                details["sha256"] = TryHashFile(mapped.Path) ?? string.Empty;
                details["related_recent_evidence"] = SummarizeRelatedSignals(0, target.ProcessId);
                details["evidence_folder_path"] = GetCaseFolder(details["case_id"]);

                DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                    "TargetInteraction",
                    !signature.IsTrusted ? "UnsignedMappedDllInTarget" : "SuspiciousMappedDllLocation",
                    !signature.IsTrusted ? EventSeverity.Critical : EventSeverity.High,
                    "Suspicious mapped image in protected target: " + mapped.Path,
                    mapped.Path,
                    target.ProcessId,
                    target.ProcessName,
                    details);

                _logger.Log(detectionEvent);
                AppendCaseEvent(details["case_id"], detectionEvent);
            }

            if (mapped.Type == NativeMethods.MEM_IMAGE &&
                !processModulePaths.Contains(NormalizePath(mapped.Path), StringComparer.OrdinalIgnoreCase))
            {
                Dictionary<string, string> details = BuildTargetBaseDetails(target, null);
                details["case_id"] = GetOrCreateCaseId(0, target.ProcessId, "ModuleListMismatch");
                details["mapped_path"] = mapped.Path;
                details["mapped_base"] = "0x" + mapped.BaseAddress.ToString("X", CultureInfo.InvariantCulture);
                details["evidence_folder_path"] = GetCaseFolder(details["case_id"]);

                DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                    "TargetInteraction",
                    "MappedImageNotInModuleList",
                    EventSeverity.High,
                    "Mapped image was visible in memory but not in the process module list: " + mapped.Path,
                    mapped.Path,
                    target.ProcessId,
                    target.ProcessName,
                    details);

                _logger.Log(detectionEvent);
                AppendCaseEvent(details["case_id"], detectionEvent);
            }
        }

        private void LogTargetMemoryAnomaly(TargetProcessInfo target, string action, EventSeverity severity, NativeMethods.MEMORY_BASIC_INFORMATION info, bool hasPeHeader)
        {
            string key = action + "|" + target.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + info.BaseAddress.ToInt64().ToString("X", CultureInfo.InvariantCulture);
            lock (_reportedMemoryKeys)
            {
                if (!_reportedMemoryKeys.Add(key))
                {
                    return;
                }
            }

            string caseId = GetOrCreateCaseId(0, target.ProcessId, action);
            Dictionary<string, string> details = BuildTargetBaseDetails(target, null);
            details["case_id"] = caseId;
            details["evidence_folder_path"] = GetCaseFolder(caseId);
            details["base_address"] = "0x" + info.BaseAddress.ToInt64().ToString("X", CultureInfo.InvariantCulture);
            details["region_size"] = info.RegionSize.ToUInt64().ToString(CultureInfo.InvariantCulture);
            details["protection"] = "0x" + info.Protect.ToString("X", CultureInfo.InvariantCulture);
            details["has_private_pe_header"] = hasPeHeader.ToString();
            details["related_recent_evidence"] = SummarizeRelatedSignals(0, target.ProcessId);

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "TargetInteraction",
                action,
                severity,
                "Protected target has suspicious private executable memory.",
                target.Path,
                target.ProcessId,
                target.ProcessName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
        }

        private void ScanThreadStartAddresses(TargetProcessInfo target, ICollection<MemoryRegionInfo> mappedRegions)
        {
            Process process;
            try
            {
                process = Process.GetProcessById(target.ProcessId);
            }
            catch
            {
                return;
            }

            using (process)
            {
                foreach (ProcessThread thread in process.Threads)
                {
                    try
                    {
                        IntPtr startAddress;
                        if (!TryQueryThreadStartAddress(thread.Id, out startAddress) || startAddress == IntPtr.Zero)
                        {
                            continue;
                        }

                        ulong start = unchecked((ulong)startAddress.ToInt64());
                        bool insideKnownRegion = mappedRegions.Any(r => start >= r.BaseAddress && start < r.BaseAddress + r.Size);
                        if (!insideKnownRegion)
                        {
                            string key = "ThreadStartOutsideModule|" + target.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + thread.Id.ToString(CultureInfo.InvariantCulture) + "|" + start.ToString("X", CultureInfo.InvariantCulture);
                            lock (_reportedMemoryKeys)
                            {
                                if (!_reportedMemoryKeys.Add(key))
                                {
                                    continue;
                                }
                            }

                            string caseId = GetOrCreateCaseId(0, target.ProcessId, "ThreadStartOutsideModule");
                            Dictionary<string, string> details = BuildTargetBaseDetails(target, null);
                            details["case_id"] = caseId;
                            details["evidence_folder_path"] = GetCaseFolder(caseId);
                            details["thread_id"] = thread.Id.ToString(CultureInfo.InvariantCulture);
                            details["thread_start_address"] = "0x" + start.ToString("X", CultureInfo.InvariantCulture);
                            details["related_recent_evidence"] = SummarizeRelatedSignals(0, target.ProcessId);

                            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                                "TargetInteraction",
                                "ThreadStartOutsideKnownModule",
                                EventSeverity.High,
                                "Protected target thread starts outside known mapped module ranges.",
                                target.Path,
                                target.ProcessId,
                                target.ProcessName,
                                details);

                            _logger.Log(detectionEvent);
                            AppendCaseEvent(caseId, detectionEvent);
                        }
                    }
                    catch
                    {
                    }
                }
            }
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

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed || detectionEvent == null || detectionEvent.Category.StartsWith("TargetInteraction", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (!IsRelatedSignal(detectionEvent))
            {
                return;
            }

            RelatedSignal signal = new RelatedSignal
            {
                TimestampUtc = detectionEvent.TimestampUtc.UtcDateTime,
                Category = detectionEvent.Category,
                Action = detectionEvent.Action,
                Description = detectionEvent.Description,
                ProcessId = detectionEvent.ProcessId,
                ProcessName = detectionEvent.ProcessName,
                Path = detectionEvent.Path,
                Summary = detectionEvent.Category + "/" + detectionEvent.Action + " " + detectionEvent.Description
            };

            string caseId;
            if (detectionEvent.Details.TryGetValue("case_id", out caseId))
            {
                signal.CaseId = caseId;
            }

            _recentSignals.Enqueue(signal);

            if (detectionEvent.Action.IndexOf("SuspiciousDeviceHandle", StringComparison.OrdinalIgnoreCase) >= 0 &&
                detectionEvent.ProcessId.HasValue)
            {
                _recentDeviceHandleByProcess[detectionEvent.ProcessId.Value] = DateTime.UtcNow;
            }

            LinkSignalToActiveCases(signal);
            CleanupRecentSignals();
        }

        private bool IsRelatedSignal(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Severity >= EventSeverity.High)
            {
                return true;
            }

            string combined = (detectionEvent.Category + " " + detectionEvent.Action + " " + detectionEvent.Description + " " + detectionEvent.Path).ToLowerInvariant();
            string[] terms =
            {
                "loader", "driver", ".sys", ".dll", "device", "section", "pipe", "mapped", "memory",
                "codeintegrity", "serviceinstalled", "shortlived", "untrusted", "unsigned", "hiddenkernel"
            };

            foreach (string term in terms)
            {
                if (combined.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private void LinkSignalToActiveCases(RelatedSignal signal)
        {
            foreach (TargetCase targetCase in _activeCases.Values)
            {
                if (DateTime.UtcNow.Subtract(targetCase.LastUpdatedUtc) > RelatedEvidenceWindow)
                {
                    continue;
                }

                if (signal.ProcessId.HasValue &&
                    signal.ProcessId.Value != targetCase.SourceProcessId &&
                    signal.ProcessId.Value != targetCase.TargetProcessId)
                {
                    continue;
                }

                Dictionary<string, string> details = new Dictionary<string, string>
                {
                    { "case_id", targetCase.CaseId },
                    { "evidence_folder_path", targetCase.EvidenceFolder },
                    { "linked_category", signal.Category ?? string.Empty },
                    { "linked_action", signal.Action ?? string.Empty },
                    { "linked_description", signal.Description ?? string.Empty },
                    { "linked_process_id", signal.ProcessId.HasValue ? signal.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty },
                    { "linked_path", signal.Path ?? string.Empty }
                };

                DetectionEvent linkedEvent = DetectionEvent.Create(
                    "TargetInteraction",
                    "CaseLinkedEvidence",
                    EventSeverity.Medium,
                    "Related suspicious evidence linked to target interaction case.",
                    signal.Path,
                    null,
                    details);

                _logger.Log(linkedEvent);
                AppendCaseEvent(targetCase.CaseId, linkedEvent);
                targetCase.LastUpdatedUtc = DateTime.UtcNow;
            }
        }

        private string GetOrCreateCaseId(int sourcePid, int targetPid, string reason)
        {
            string key = sourcePid.ToString(CultureInfo.InvariantCulture) + "|" + targetPid.ToString(CultureInfo.InvariantCulture);
            TargetCase existing;
            if (_activeCases.TryGetValue(key, out existing) &&
                DateTime.UtcNow.Subtract(existing.LastUpdatedUtc) <= RelatedEvidenceWindow)
            {
                existing.LastUpdatedUtc = DateTime.UtcNow;
                return existing.CaseId;
            }

            string caseId = "CASE-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string folder = GetCaseFolder(caseId);
            Directory.CreateDirectory(folder);

            TargetCase targetCase = new TargetCase
            {
                CaseId = caseId,
                SourceProcessId = sourcePid,
                TargetProcessId = targetPid,
                CreatedUtc = DateTime.UtcNow,
                LastUpdatedUtc = DateTime.UtcNow,
                EvidenceFolder = folder,
                Reason = reason
            };

            _activeCases[key] = targetCase;
            return caseId;
        }

        private string GetCaseFolder(string caseId)
        {
            return Path.Combine(_caseRoot, caseId);
        }

        private void AppendCaseEvent(string caseId, DetectionEvent detectionEvent)
        {
            try
            {
                string folder = GetCaseFolder(caseId);
                Directory.CreateDirectory(folder);
                string path = Path.Combine(folder, "target-interaction-case.jsonl");
                lock (_reportLock)
                {
                    File.AppendAllText(path, CaseEventToJson(detectionEvent) + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch
            {
            }
        }

        private static string CaseEventToJson(DetectionEvent detectionEvent)
        {
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "timestamp_utc", detectionEvent.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "category", detectionEvent.Category, ref first);
            JsonUtilities.AppendStringProperty(builder, "action", detectionEvent.Action, ref first);
            JsonUtilities.AppendStringProperty(builder, "severity", detectionEvent.Severity.ToString(), ref first);
            JsonUtilities.AppendStringProperty(builder, "description", detectionEvent.Description, ref first);
            JsonUtilities.AppendStringProperty(builder, "path", detectionEvent.Path, ref first);
            JsonUtilities.AppendStringProperty(builder, "process_name", detectionEvent.ProcessName, ref first);
            JsonUtilities.AppendNumberProperty(builder, "process_id", detectionEvent.ProcessId.HasValue ? detectionEvent.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : "0", ref first);
            builder.Append(",\"details\":{");
            bool firstDetail = true;
            foreach (KeyValuePair<string, string> pair in detectionEvent.Details)
            {
                JsonUtilities.AppendStringProperty(builder, pair.Key, pair.Value, ref firstDetail);
            }
            builder.Append("}}");
            return builder.ToString();
        }

        private Dictionary<string, string> BuildTargetBaseDetails(TargetProcessInfo target, ProcessInfo source)
        {
            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "target_process_id", target.ProcessId.ToString(CultureInfo.InvariantCulture) },
                { "target_process_name", target.ProcessName ?? string.Empty },
                { "target_path", target.Path ?? string.Empty }
            };

            if (source != null)
            {
                details["source_process_id"] = source.ProcessId.ToString(CultureInfo.InvariantCulture);
                details["source_process_name"] = source.Name ?? string.Empty;
                details["source_path"] = source.Path ?? string.Empty;
            }

            return details;
        }

        private string SummarizeRelatedSignals(int sourcePid, int targetPid)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(RelatedEvidenceWindow);
            return string.Join(" || ", _recentSignals
                .Where(s => s.TimestampUtc >= cutoff &&
                            (!s.ProcessId.HasValue || s.ProcessId.Value == sourcePid || s.ProcessId.Value == targetPid ||
                             s.Category.IndexOf("HiddenKernel", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             s.Action.IndexOf("Driver", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             s.Action.IndexOf("Dll", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             s.Action.IndexOf("Mapped", StringComparison.OrdinalIgnoreCase) >= 0))
                .Select(s => s.Summary)
                .Take(12)
                .ToArray());
        }

        private void CleanupRecentSignals()
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(RelatedEvidenceWindow);
            while (_recentSignals.TryPeek(out RelatedSignal signal) && signal.TimestampUtc < cutoff)
            {
                RelatedSignal ignored;
                _recentSignals.TryDequeue(out ignored);
            }

            foreach (KeyValuePair<int, DateTime> pair in _recentDeviceHandleByProcess.ToArray())
            {
                if (pair.Value < cutoff)
                {
                    DateTime ignored;
                    _recentDeviceHandleByProcess.TryRemove(pair.Key, out ignored);
                }
            }
        }

        private string CollectSourceCommunicationObjects(int sourcePid)
        {
            List<string> objects = new List<string>();
            IntPtr buffer = IntPtr.Zero;
            try
            {
                int length = 1024 * 1024;
                int returnedLength;
                int status = NativeMethods.NtQuerySystemInformation(NativeMethods.SystemExtendedHandleInformation, IntPtr.Zero, 0, out returnedLength);
                length = Math.Max(length, returnedLength + 1024);
                buffer = Marshal.AllocHGlobal(length);
                status = NativeMethods.NtQuerySystemInformation(NativeMethods.SystemExtendedHandleInformation, buffer, length, out returnedLength);
                if (status != 0)
                {
                    return string.Empty;
                }

                long handleCount = Marshal.ReadIntPtr(buffer).ToInt64();
                IntPtr entryPtr = IntPtr.Add(buffer, IntPtr.Size * 2);
                int entrySize = Marshal.SizeOf(typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                int collected = 0;

                for (long i = 0; i < handleCount && collected < 64; i++)
                {
                    NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry =
                        (NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(entryPtr, typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                    entryPtr = IntPtr.Add(entryPtr, entrySize);

                    int pid = unchecked((int)entry.UniqueProcessId.ToUInt64());
                    if (pid != sourcePid)
                    {
                        continue;
                    }

                    string description = TryDescribeHandle(sourcePid, entry);
                    if (!string.IsNullOrWhiteSpace(description) &&
                        (description.IndexOf("\\Device\\NamedPipe", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         description.IndexOf("\\BaseNamedObjects", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         description.IndexOf("\\Device\\", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        objects.Add(description);
                        collected++;
                    }
                }
            }
            catch
            {
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return string.Join(" | ", objects.ToArray());
        }

        private string TryDescribeHandle(int sourcePid, NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry)
        {
            IntPtr sourceProcessHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_DUP_HANDLE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, sourcePid);
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
                string name = QueryObjectString(duplicatedHandle, NativeMethods.ObjectNameInformation);
                if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(name))
                {
                    return null;
                }

                return type + ":" + name + ":0x" + entry.GrantedAccess.ToString("X", CultureInfo.InvariantCulture);
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

        private static uint SuspiciousProcessAccessMask()
        {
            return NativeMethods.PROCESS_VM_READ |
                   NativeMethods.PROCESS_VM_WRITE |
                   NativeMethods.PROCESS_VM_OPERATION |
                   NativeMethods.PROCESS_CREATE_THREAD |
                   NativeMethods.PROCESS_DUP_HANDLE |
                   NativeMethods.PROCESS_QUERY_INFORMATION |
                   NativeMethods.PROCESS_SUSPEND_RESUME;
        }

        private static bool HasAccess(uint grantedAccess, uint access)
        {
            return (grantedAccess & access) == access;
        }

        private static string DecodeProcessAccess(uint access)
        {
            List<string> rights = new List<string>();
            AddRight(rights, access, NativeMethods.PROCESS_VM_READ, "PROCESS_VM_READ");
            AddRight(rights, access, NativeMethods.PROCESS_VM_WRITE, "PROCESS_VM_WRITE");
            AddRight(rights, access, NativeMethods.PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION");
            AddRight(rights, access, NativeMethods.PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD");
            AddRight(rights, access, NativeMethods.PROCESS_DUP_HANDLE, "PROCESS_DUP_HANDLE");
            AddRight(rights, access, NativeMethods.PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION");
            AddRight(rights, access, NativeMethods.PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME");
            return string.Join("|", rights.ToArray());
        }

        private static void AddRight(ICollection<string> rights, uint access, uint mask, string name)
        {
            if (HasAccess(access, mask))
            {
                rights.Add(name);
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

        private bool LooksLikePeHeader(IntPtr processHandle, IntPtr baseAddress)
        {
            byte[] header = new byte[0x400];
            IntPtr bytesRead;
            if (!NativeMethods.ReadProcessMemory(processHandle, baseAddress, header, header.Length, out bytesRead) || bytesRead.ToInt64() < 0x100)
            {
                return false;
            }

            if (header[0] != (byte)'M' || header[1] != (byte)'Z')
            {
                return false;
            }

            int peOffset = BitConverter.ToInt32(header, 0x3C);
            return peOffset > 0 && peOffset + 4 < header.Length &&
                   header[peOffset] == (byte)'P' &&
                   header[peOffset + 1] == (byte)'E' &&
                   header[peOffset + 2] == 0 &&
                   header[peOffset + 3] == 0;
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

        private static List<string> GetProcessModulePaths(int processId)
        {
            List<string> paths = new List<string>();
            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        try
                        {
                            paths.Add(NormalizePath(module.FileName));
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

            return paths;
        }

        private static string NormalizePath(string path)
        {
            try
            {
                return string.IsNullOrWhiteSpace(path) ? path : Path.GetFullPath(path);
            }
            catch
            {
                return path;
            }
        }

        private ProcessInfo BuildProcessInfo(int processId)
        {
            return new ProcessInfo
            {
                ProcessId = processId,
                Name = TryGetProcessName(processId),
                Path = TryGetProcessPath(processId)
            };
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

        private static string TryGetProcessPath(int processId)
        {
            try
            {
                string query = "SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + processId.ToString(CultureInfo.InvariantCulture);
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        using (obj)
                        {
                            return Convert.ToString(obj["ExecutablePath"], CultureInfo.InvariantCulture);
                        }
                    }
                }
            }
            catch
            {
            }

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

        private static string SafeProcessName(Process process)
        {
            try
            {
                return process.ProcessName;
            }
            catch
            {
                return null;
            }
        }

        private static string BuildParentProcessChain(int processId)
        {
            List<string> chain = new List<string>();
            HashSet<int> seen = new HashSet<int>();
            int current = processId;

            for (int depth = 0; depth < 8; depth++)
            {
                if (current <= 0 || !seen.Add(current))
                {
                    break;
                }

                ProcessInfo info = QueryProcessParent(current);
                if (info == null)
                {
                    break;
                }

                chain.Add(info.ProcessId.ToString(CultureInfo.InvariantCulture) + ":" + (info.Name ?? "unknown") + ":" + (info.Path ?? string.Empty));
                current = info.ParentProcessId;
            }

            return string.Join(" <- ", chain.ToArray());
        }

        private static ProcessInfo QueryProcessParent(int processId)
        {
            try
            {
                string query = "SELECT ProcessId, ParentProcessId, Name, ExecutablePath FROM Win32_Process WHERE ProcessId = " + processId.ToString(CultureInfo.InvariantCulture);
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject obj in results)
                    {
                        using (obj)
                        {
                            return new ProcessInfo
                            {
                                ProcessId = Convert.ToInt32(obj["ProcessId"], CultureInfo.InvariantCulture),
                                ParentProcessId = Convert.ToInt32(obj["ParentProcessId"], CultureInfo.InvariantCulture),
                                Name = Convert.ToString(obj["Name"], CultureInfo.InvariantCulture),
                                Path = Convert.ToString(obj["ExecutablePath"], CultureInfo.InvariantCulture)
                            };
                        }
                    }
                }
            }
            catch
            {
            }

            return null;
        }

        private string TryHashFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                return null;
            }

            Dictionary<string, string> details = FileClassifier.BuildFileDetails(path, _options, true);
            string hash;
            return details.TryGetValue("sha256", out hash) ? hash : null;
        }

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
            _stopSignal.Set();

            if (_thread != null && _thread.IsAlive)
            {
                _thread.Join(TimeSpan.FromSeconds(2));
            }

            _stopSignal.Dispose();
        }

        private sealed class TargetProcessInfo
        {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string Path { get; set; }
        }

        private sealed class ProcessInfo
        {
            public int ProcessId { get; set; }
            public int ParentProcessId { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
        }

        private sealed class MemoryRegionInfo
        {
            public ulong BaseAddress { get; set; }
            public ulong Size { get; set; }
            public uint Protection { get; set; }
            public uint Type { get; set; }
            public string Path { get; set; }
        }

        private sealed class RelatedSignal
        {
            public DateTime TimestampUtc { get; set; }
            public string Category { get; set; }
            public string Action { get; set; }
            public string Description { get; set; }
            public int? ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string Path { get; set; }
            public string Summary { get; set; }
            public string CaseId { get; set; }
        }

        private sealed class TargetCase
        {
            public string CaseId { get; set; }
            public int SourceProcessId { get; set; }
            public int TargetProcessId { get; set; }
            public DateTime CreatedUtc { get; set; }
            public DateTime LastUpdatedUtc { get; set; }
            public string EvidenceFolder { get; set; }
            public string Reason { get; set; }
        }
    }
}
