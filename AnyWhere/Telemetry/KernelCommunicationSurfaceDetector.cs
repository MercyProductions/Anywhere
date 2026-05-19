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
    internal sealed class KernelCommunicationSurfaceDetector : IDetectionMonitor
    {
        private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(10);

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private readonly ConcurrentQueue<RecentSignal> _recentSignals = new ConcurrentQueue<RecentSignal>();
        private readonly ConcurrentDictionary<int, DateTime> _recentDeviceProcessIds = new ConcurrentDictionary<int, DateTime>();
        private readonly ConcurrentDictionary<int, DateTime> _recentTargetProcessIds = new ConcurrentDictionary<int, DateTime>();
        private readonly ConcurrentDictionary<string, SignatureVerificationResult> _signatureCache = new ConcurrentDictionary<string, SignatureVerificationResult>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, CommunicationCase> _cases = new ConcurrentDictionary<string, CommunicationCase>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _seenDeviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _syncRoot = new object();
        private readonly object _caseWriteLock = new object();
        private readonly string _caseRoot;
        private Thread _thread;
        private bool _disposed;
        private bool _baselineComplete;

        public KernelCommunicationSurfaceDetector(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _caseRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Kernel Communication Cases");
        }

        public string Name
        {
            get { return "Kernel Communication Surface"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_caseRoot);
            _logger.EventLogged += OnEventLogged;
            BaselineDosDevices();

            _thread = new Thread(ThreadMain)
            {
                IsBackground = true,
                Name = "Aegis Kernel Communication Surface Detector"
            };
            _thread.Start();

            _logger.Log(DetectionEvent.Create(
                "KernelComm",
                "Started",
                EventSeverity.Low,
                "Kernel communication surface detector started in evidence-only mode.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "scan_interval_seconds", _options.KernelCommunicationScanInterval.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "max_handles", _options.MaxKernelCommunicationHandlesToInspect.ToString(CultureInfo.InvariantCulture) },
                    { "case_root", _caseRoot },
                    { "visibility", "Visible user-mode handle and DOS-device namespace enumeration only." }
                }));
        }

        private void ThreadMain()
        {
            while (!_stopSignal.Wait(_options.KernelCommunicationScanInterval))
            {
                try
                {
                    ScanDosDevices();
                    ScanHandleSurfaces();
                }
                catch (Exception ex)
                {
                    _logger.LogException("KernelComm", "ScanFailed", ex, null);
                }

                CleanupRecentSignals();
            }
        }

        private void BaselineDosDevices()
        {
            foreach (string name in EnumerateDosDeviceNames())
            {
                _seenDeviceNames.Add(name);
            }

            _baselineComplete = true;
        }

        private void ScanDosDevices()
        {
            foreach (string name in EnumerateDosDeviceNames())
            {
                bool isNew;
                lock (_syncRoot)
                {
                    isNew = _seenDeviceNames.Add(name);
                }

                if (!isNew || !_baselineComplete)
                {
                    continue;
                }

                bool randomized = LooksRandomizedName(name);
                bool nearLoader = HasRecentSignal("Loader") || HasRecentSignal("Driver") || HasRecentSignal("UntrustedDriverDropped");
                if (randomized || nearLoader || IsSuspiciousDeviceName(name))
                {
                    string caseId = GetOrCreateCase("device|" + name, 0, 0, "DeviceDiscovery");
                    Dictionary<string, string> details = new Dictionary<string, string>
                    {
                        { "case_id", caseId },
                        { "evidence_folder_path", GetCaseFolder(caseId) },
                        { "object_type", "DosDevice" },
                        { "object_name", name },
                        { "randomized_name", randomized.ToString() },
                        { "near_loader_or_driver_activity", nearLoader.ToString() },
                        { "related_recent_evidence", SummarizeRecentSignals(0) },
                        { "confidence_score", (randomized && nearLoader ? 0.85 : 0.65).ToString("0.00", CultureInfo.InvariantCulture) }
                    };

                    DetectionEvent detectionEvent = DetectionEvent.Create(
                        "KernelComm",
                        "NewSuspiciousDeviceName",
                        randomized && nearLoader ? EventSeverity.High : EventSeverity.Medium,
                        "New visible device name appeared: " + name,
                        name,
                        null,
                        details);

                    _logger.Log(detectionEvent);
                    AppendCaseEvent(caseId, detectionEvent);
                }
            }
        }

        private void ScanHandleSurfaces()
        {
            if (_options.MaxKernelCommunicationHandlesToInspect <= 0)
            {
                return;
            }

            List<ObjectHandleRecord> records = EnumerateInterestingHandles(_options.MaxKernelCommunicationHandlesToInspect);
            Dictionary<string, List<ObjectHandleRecord>> sections = new Dictionary<string, List<ObjectHandleRecord>>(StringComparer.OrdinalIgnoreCase);

            foreach (ObjectHandleRecord record in records)
            {
                if (record.ObjectType.Equals("Section", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(record.ObjectName))
                {
                    List<ObjectHandleRecord> list;
                    if (!sections.TryGetValue(record.ObjectName, out list))
                    {
                        list = new List<ObjectHandleRecord>();
                        sections[record.ObjectName] = list;
                    }

                    list.Add(record);
                }

                EvaluateHandleRecord(record);
            }

            EvaluateSharedSections(sections);
        }

        private List<ObjectHandleRecord> EnumerateInterestingHandles(int maxHandles)
        {
            List<ObjectHandleRecord> records = new List<ObjectHandleRecord>();
            Dictionary<int, ProcessIdentity> identityCache = new Dictionary<int, ProcessIdentity>();
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
                        return records;
                    }

                    length = Math.Max(length * 2, returnedLength + 1024);
                }

                if (buffer == IntPtr.Zero)
                {
                    return records;
                }

                long handleCount = Marshal.ReadIntPtr(buffer).ToInt64();
                IntPtr entryPtr = IntPtr.Add(buffer, IntPtr.Size * 2);
                int entrySize = Marshal.SizeOf(typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                int inspected = 0;

                for (long i = 0; i < handleCount && inspected < maxHandles; i++)
                {
                    NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry =
                        (NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(entryPtr, typeof(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                    entryPtr = IntPtr.Add(entryPtr, entrySize);
                    inspected++;

                    int processId = unchecked((int)entry.UniqueProcessId.ToUInt64());
                    if (processId <= 4)
                    {
                        continue;
                    }

                    ObjectHandleRecord record = TryInspectHandle(processId, entry, identityCache);
                    if (record != null && IsInterestingObject(record))
                    {
                        records.Add(record);
                    }
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return records;
        }

        private ObjectHandleRecord TryInspectHandle(int processId, NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry, Dictionary<int, ProcessIdentity> identityCache)
        {
            IntPtr processHandle = NativeMethods.OpenProcess(NativeMethods.PROCESS_DUP_HANDLE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (processHandle == IntPtr.Zero)
            {
                return null;
            }

            IntPtr duplicatedHandle = IntPtr.Zero;
            try
            {
                if (!NativeMethods.DuplicateHandle(
                    processHandle,
                    new IntPtr(unchecked((long)entry.HandleValue.ToUInt64())),
                    NativeMethods.GetCurrentProcess(),
                    out duplicatedHandle,
                    0,
                    false,
                    NativeMethods.DUPLICATE_SAME_ACCESS))
                {
                    return null;
                }

                string objectType = QueryObjectString(duplicatedHandle, NativeMethods.ObjectTypeInformation);
                if (string.IsNullOrWhiteSpace(objectType) || !IsPotentialCommunicationType(objectType))
                {
                    return null;
                }

                ProcessIdentity identity = null;
                if (objectType.Equals("File", StringComparison.OrdinalIgnoreCase))
                {
                    identity = GetCachedProcessIdentity(processId, identityCache);
                    if (!ShouldInspectFileHandle(processId, identity))
                    {
                        return null;
                    }
                }

                string objectName = QueryObjectString(duplicatedHandle, NativeMethods.ObjectNameInformation);
                int targetProcessId = 0;
                if (objectType.Equals("Process", StringComparison.OrdinalIgnoreCase))
                {
                    targetProcessId = NativeMethods.GetProcessId(duplicatedHandle);
                    objectName = targetProcessId > 0 ? "Process:" + targetProcessId.ToString(CultureInfo.InvariantCulture) : objectName;
                }

                if (identity == null)
                {
                    identity = GetCachedProcessIdentity(processId, identityCache);
                }

                return new ObjectHandleRecord
                {
                    ProcessId = processId,
                    ProcessName = identity.Name,
                    ProcessPath = identity.Path,
                    ParentProcessId = identity.ParentProcessId,
                    ObjectType = objectType,
                    ObjectName = objectName,
                    GrantedAccess = entry.GrantedAccess,
                    HandleValue = entry.HandleValue.ToUInt64(),
                    TargetProcessId = targetProcessId
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

                NativeMethods.CloseHandle(processHandle);
            }
        }

        private ProcessIdentity GetCachedProcessIdentity(int processId, Dictionary<int, ProcessIdentity> identityCache)
        {
            ProcessIdentity identity;
            if (identityCache != null && identityCache.TryGetValue(processId, out identity))
            {
                return identity;
            }

            identity = QueryProcessIdentity(processId);
            if (identityCache != null)
            {
                identityCache[processId] = identity;
            }

            return identity;
        }

        private bool ShouldInspectFileHandle(int processId, ProcessIdentity identity)
        {
            if (identity == null)
            {
                return false;
            }

            return IsProcessSuspicious(processId, identity.Name, identity.Path) ||
                   TargetProcessMatcher.IsProtectedProcessName(identity.Name, _options.ProtectedProcessNames) ||
                   HasRecentSignal("Loader") ||
                   HasRecentSignal("TargetInteraction") ||
                   HasRecentSignal("Driver");
        }

        private void EvaluateHandleRecord(ObjectHandleRecord record)
        {
            if (string.IsNullOrWhiteSpace(record.ObjectName) && !record.ObjectType.Equals("Process", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            bool processSuspicious = IsProcessSuspicious(record.ProcessId, record.ProcessName, record.ProcessPath);
            bool objectSuspicious = IsSuspiciousCommunicationObject(record);
            bool protectedTargetHandle = record.TargetProcessId > 0 && IsProtectedProcess(record.TargetProcessId);
            bool writableOrExecutableSection = record.ObjectType.Equals("Section", StringComparison.OrdinalIgnoreCase) && IsWritableOrExecutableSectionAccess(record.GrantedAccess);
            SignatureVerificationResult signature = GetSignature(record.ProcessPath);
            bool sourceUntrusted = signature == null || !signature.IsTrusted;
            bool unsignedUnknownDevice = sourceUntrusted && IsUnknownDeviceObject(record);

            if (!processSuspicious && !objectSuspicious && !protectedTargetHandle && !writableOrExecutableSection && !unsignedUnknownDevice)
            {
                return;
            }

            string key = record.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" +
                         record.ObjectType + "|" +
                         (record.ObjectName ?? string.Empty) + "|" +
                         record.GrantedAccess.ToString("X", CultureInfo.InvariantCulture);
            lock (_syncRoot)
            {
                if (!_reportedKeys.Add(key))
                {
                    return;
                }
            }

            if (record.ObjectType.Equals("Device", StringComparison.OrdinalIgnoreCase) ||
                record.ObjectType.Equals("Section", StringComparison.OrdinalIgnoreCase) ||
                record.ObjectType.IndexOf("Port", StringComparison.OrdinalIgnoreCase) >= 0 ||
                (record.ObjectName ?? string.Empty).StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
            {
                _recentDeviceProcessIds[record.ProcessId] = DateTime.UtcNow;
            }

            if (protectedTargetHandle)
            {
                _recentTargetProcessIds[record.ProcessId] = DateTime.UtcNow;
            }

            string caseId = GetOrCreateCase("comm|" + record.ProcessId.ToString(CultureInfo.InvariantCulture), record.ProcessId, record.TargetProcessId, "CommunicationSurface");
            double confidence = ScoreConfidence(record, processSuspicious, objectSuspicious, protectedTargetHandle, writableOrExecutableSection, signature);
            EventSeverity severity = SeverityFromConfidence(confidence);

            Dictionary<string, string> details = BuildHandleDetails(record, caseId, signature, confidence);
            details["process_suspicious"] = processSuspicious.ToString();
            details["object_suspicious"] = objectSuspicious.ToString();
            details["protected_target_handle"] = protectedTargetHandle.ToString();
            details["writable_or_executable_section"] = writableOrExecutableSection.ToString();
            details["unsigned_unknown_device"] = unsignedUnknownDevice.ToString();
            details["related_recent_evidence"] = SummarizeRecentSignals(record.ProcessId);

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "KernelComm",
                ActionForRecord(record, protectedTargetHandle, writableOrExecutableSection),
                severity,
                "Suspicious kernel/shared-memory communication surface observed: " + record.ProcessName + " -> " + record.ObjectType + " " + record.ObjectName,
                record.ObjectName,
                record.ProcessId,
                record.ProcessName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
            TryEmitCommunicationChainCase(record, caseId);
        }

        private void EvaluateSharedSections(Dictionary<string, List<ObjectHandleRecord>> sections)
        {
            foreach (KeyValuePair<string, List<ObjectHandleRecord>> pair in sections)
            {
                if (string.IsNullOrWhiteSpace(pair.Key) || !IsUnusualSectionName(pair.Key))
                {
                    continue;
                }

                List<ObjectHandleRecord> handles = pair.Value;
                List<ObjectHandleRecord> protectedHandles = handles.Where(h => IsProtectedProcess(h.ProcessId)).ToList();
                List<ObjectHandleRecord> suspiciousHandles = handles.Where(h => IsProcessSuspicious(h.ProcessId, h.ProcessName, h.ProcessPath)).ToList();

                if (protectedHandles.Count == 0 || suspiciousHandles.Count == 0)
                {
                    continue;
                }

                foreach (ObjectHandleRecord suspicious in suspiciousHandles)
                {
                    foreach (ObjectHandleRecord target in protectedHandles)
                    {
                        string key = "shared|" + pair.Key + "|" + suspicious.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + target.ProcessId.ToString(CultureInfo.InvariantCulture);
                        lock (_syncRoot)
                        {
                            if (!_reportedKeys.Add(key))
                            {
                                continue;
                            }
                        }

                        string caseId = GetOrCreateCase("shared|" + suspicious.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + target.ProcessId.ToString(CultureInfo.InvariantCulture), suspicious.ProcessId, target.ProcessId, "SharedSection");
                        SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(suspicious.ProcessPath);
                        double confidence = IsWritableOrExecutableSectionAccess(suspicious.GrantedAccess) ? 0.9 : 0.78;

                        Dictionary<string, string> details = BuildHandleDetails(suspicious, caseId, signature, confidence);
                        details["shared_section_name"] = pair.Key;
                        details["target_process_id"] = target.ProcessId.ToString(CultureInfo.InvariantCulture);
                        details["target_process_name"] = target.ProcessName ?? string.Empty;
                        details["target_section_access"] = "0x" + target.GrantedAccess.ToString("X", CultureInfo.InvariantCulture);
                        details["target_section_decoded_access"] = DecodeSectionAccess(target.GrantedAccess);
                        details["related_recent_evidence"] = SummarizeRecentSignals(suspicious.ProcessId);

                        DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                            "KernelComm",
                            "SuspiciousSharedSectionWithTarget",
                            confidence >= 0.85 ? EventSeverity.Critical : EventSeverity.High,
                            "Suspicious process and protected target share a named section: " + pair.Key,
                            pair.Key,
                            suspicious.ProcessId,
                            suspicious.ProcessName,
                            details);

                        _logger.Log(detectionEvent);
                        AppendCaseEvent(caseId, detectionEvent);
                    }
                }
            }
        }

        private void TryEmitCommunicationChainCase(ObjectHandleRecord record, string caseId)
        {
            bool hasDeviceOrSection = _recentDeviceProcessIds.ContainsKey(record.ProcessId);
            bool hasTarget = _recentTargetProcessIds.ContainsKey(record.ProcessId) || record.TargetProcessId > 0;
            bool hasMemory = HasRecentSignal("PrivateExecutableMemory") || HasRecentSignal("RwxPrivateMemory") || HasRecentSignal("PrivatePeHeader");
            bool hasDriver = HasRecentSignal("Driver") || HasRecentSignal("HiddenKernel") || HasRecentSignal("Vulnerable");

            if (!(hasDeviceOrSection && hasTarget && (hasMemory || hasDriver)))
            {
                return;
            }

            string key = "chain|" + record.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + caseId;
            lock (_syncRoot)
            {
                if (!_reportedKeys.Add(key))
                {
                    return;
                }
            }

            Dictionary<string, string> details = BuildHandleDetails(record, caseId, GetSignature(record.ProcessPath), 0.95);
            details["chain_loader_or_controller"] = record.ProcessName ?? string.Empty;
            details["chain_opened_device_or_section"] = (record.ObjectType ?? string.Empty) + ":" + (record.ObjectName ?? string.Empty);
            details["chain_target_game_interaction"] = hasTarget.ToString();
            details["chain_suspicious_memory_state"] = hasMemory.ToString();
            details["chain_driver_or_vulnerable_activity"] = hasDriver.ToString();
            details["related_recent_evidence"] = SummarizeRecentSignals(record.ProcessId);

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "KernelComm",
                "CommunicationChainCorrelated",
                EventSeverity.Critical,
                "Communication chain correlated: controller/device or section activity, protected target interaction, and related suspicious evidence.",
                record.ObjectName,
                record.ProcessId,
                record.ProcessName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
        }

        private Dictionary<string, string> BuildHandleDetails(ObjectHandleRecord record, string caseId, SignatureVerificationResult signature, double confidence)
        {
            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "case_id", caseId },
                { "evidence_folder_path", GetCaseFolder(caseId) },
                { "source_process_id", record.ProcessId.ToString(CultureInfo.InvariantCulture) },
                { "source_process_name", record.ProcessName ?? string.Empty },
                { "parent_process_id", record.ParentProcessId.ToString(CultureInfo.InvariantCulture) },
                { "source_path", record.ProcessPath ?? string.Empty },
                { "source_sha256", TryHashFile(record.ProcessPath) ?? string.Empty },
                { "source_signature_status", signature == null ? string.Empty : signature.Status ?? string.Empty },
                { "source_signature_subject", signature == null ? string.Empty : signature.Subject ?? string.Empty },
                { "object_type", record.ObjectType ?? string.Empty },
                { "object_name", record.ObjectName ?? string.Empty },
                { "access_rights", "0x" + record.GrantedAccess.ToString("X", CultureInfo.InvariantCulture) },
                { "decoded_access", DecodeObjectAccess(record) },
                { "handle_value", "0x" + record.HandleValue.ToString("X", CultureInfo.InvariantCulture) },
                { "target_process_id", record.TargetProcessId > 0 ? record.TargetProcessId.ToString(CultureInfo.InvariantCulture) : string.Empty },
                { "related_files", SummarizeRecentPaths() },
                { "related_memory_findings", SummarizeRecentMemoryFindings() },
                { "confidence_score", confidence.ToString("0.00", CultureInfo.InvariantCulture) },
                { "visibility", "Evidence-only user-mode object handle inspection; no IOCTLs sent and no objects modified." }
            };

            if (record.TargetProcessId > 0)
            {
                ProcessIdentity target = QueryProcessIdentity(record.TargetProcessId);
                SignatureVerificationResult targetSignature = GetSignature(target.Path);
                details["target_process_name"] = target.Name ?? string.Empty;
                details["target_path"] = target.Path ?? string.Empty;
                details["target_sha256"] = TryHashFile(target.Path) ?? string.Empty;
                details["target_signature_status"] = targetSignature == null ? string.Empty : targetSignature.Status ?? string.Empty;
                details["target_signature_subject"] = targetSignature == null ? string.Empty : targetSignature.Subject ?? string.Empty;
            }

            return details;
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed || detectionEvent == null || detectionEvent.Category.StartsWith("KernelComm", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            RecentSignal signal = new RecentSignal
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

            if (IsRelevantSignal(signal))
            {
                _recentSignals.Enqueue(signal);
            }
        }

        private bool IsRelevantSignal(RecentSignal signal)
        {
            if (string.IsNullOrWhiteSpace(signal.Category + signal.Action + signal.Description + signal.Path))
            {
                return false;
            }

            string text = (signal.Category + " " + signal.Action + " " + signal.Description + " " + signal.Path).ToLowerInvariant();
            string[] terms =
            {
                "hiddenkernel", "targetinteraction", "driver", ".sys", ".dll", "device", "section",
                "pipe", "mapped", "privateexecutable", "rwx", "vulnerable", "untrusted", "unsigned",
                "serviceinstalled", "shortlived"
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

        private static bool IsPotentialCommunicationType(string objectType)
        {
            return objectType.Equals("Device", StringComparison.OrdinalIgnoreCase) ||
                   objectType.Equals("Section", StringComparison.OrdinalIgnoreCase) ||
                   objectType.Equals("File", StringComparison.OrdinalIgnoreCase) ||
                   objectType.Equals("ALPC Port", StringComparison.OrdinalIgnoreCase) ||
                   objectType.Equals("Port", StringComparison.OrdinalIgnoreCase) ||
                   objectType.Equals("Process", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsInterestingObject(ObjectHandleRecord record)
        {
            if (record.ObjectType.Equals("Process", StringComparison.OrdinalIgnoreCase))
            {
                return record.TargetProcessId > 0;
            }

            if (string.IsNullOrWhiteSpace(record.ObjectName))
            {
                return false;
            }

            return record.ObjectType.Equals("Device", StringComparison.OrdinalIgnoreCase) ||
                   record.ObjectType.Equals("Section", StringComparison.OrdinalIgnoreCase) ||
                   record.ObjectType.Equals("ALPC Port", StringComparison.OrdinalIgnoreCase) ||
                   record.ObjectType.Equals("Port", StringComparison.OrdinalIgnoreCase) ||
                   record.ObjectName.StartsWith("\\Device\\NamedPipe", StringComparison.OrdinalIgnoreCase) ||
                   record.ObjectName.StartsWith("\\BaseNamedObjects", StringComparison.OrdinalIgnoreCase) ||
                   record.ObjectName.StartsWith("\\Sessions\\", StringComparison.OrdinalIgnoreCase);
        }

        private bool IsSuspiciousCommunicationObject(ObjectHandleRecord record)
        {
            if (record.ObjectType.Equals("Process", StringComparison.OrdinalIgnoreCase))
            {
                return record.TargetProcessId > 0 && IsProtectedProcess(record.TargetProcessId);
            }

            string name = record.ObjectName ?? string.Empty;
            if (record.ObjectType.Equals("Device", StringComparison.OrdinalIgnoreCase) || name.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
            {
                return IsSuspiciousDeviceName(name) || LooksRandomizedName(LeafName(name)) || HasRecentSignal("Driver") || HasRecentSignal("Vulnerable");
            }

            if (record.ObjectType.Equals("Section", StringComparison.OrdinalIgnoreCase))
            {
                return IsUnusualSectionName(name) || IsWritableOrExecutableSectionAccess(record.GrantedAccess);
            }

            if (name.StartsWith("\\Device\\NamedPipe", StringComparison.OrdinalIgnoreCase))
            {
                return LooksRandomizedName(LeafName(name)) || HasRecentSignal("Loader") || HasRecentSignal("TargetInteraction");
            }

            return false;
        }

        private bool IsProcessSuspicious(int processId, string processName, string path)
        {
            if (TargetProcessMatcher.IsProtectedProcessName(processName, _options.ProtectedProcessNames))
            {
                return false;
            }

            string text = (processName + " " + path).ToLowerInvariant();
            string[] indicators =
            {
                "loader", "mapper", "kdmapper", "drvmap", "inject", "manualmap", "iqvw", "naldrv",
                "gdrv", "capcom", "dbutil", "rtcore", "winio", "mhyprot"
            };

            foreach (string indicator in indicators)
            {
                if (text.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            DateTime when;
            return _recentDeviceProcessIds.TryGetValue(processId, out when) &&
                   DateTime.UtcNow.Subtract(when) <= CorrelationWindow;
        }

        private bool IsProtectedProcess(int processId)
        {
            ProcessIdentity identity = QueryProcessIdentity(processId);
            return TargetProcessMatcher.IsProtectedProcessName(identity.Name, _options.ProtectedProcessNames) ||
                   TargetProcessMatcher.IsProtectedProcessName(identity.Path, _options.ProtectedProcessNames);
        }

        private static bool IsWritableOrExecutableSectionAccess(uint access)
        {
            return (access & NativeMethods.SECTION_MAP_WRITE) != 0 ||
                   (access & NativeMethods.SECTION_MAP_EXECUTE) != 0 ||
                   (access & 0xF001F) == 0xF001F;
        }

        private static string DecodeSectionAccess(uint access)
        {
            List<string> rights = new List<string>();
            if ((access & NativeMethods.SECTION_QUERY) != 0) rights.Add("SECTION_QUERY");
            if ((access & NativeMethods.SECTION_MAP_READ) != 0) rights.Add("SECTION_MAP_READ");
            if ((access & NativeMethods.SECTION_MAP_WRITE) != 0) rights.Add("SECTION_MAP_WRITE");
            if ((access & NativeMethods.SECTION_MAP_EXECUTE) != 0) rights.Add("SECTION_MAP_EXECUTE");
            if ((access & NativeMethods.SECTION_EXTEND_SIZE) != 0) rights.Add("SECTION_EXTEND_SIZE");
            return rights.Count == 0 ? "0x" + access.ToString("X", CultureInfo.InvariantCulture) : string.Join("|", rights.ToArray());
        }

        private static string DecodeObjectAccess(ObjectHandleRecord record)
        {
            if (record.ObjectType.Equals("Section", StringComparison.OrdinalIgnoreCase))
            {
                return DecodeSectionAccess(record.GrantedAccess);
            }

            if (record.ObjectType.Equals("Process", StringComparison.OrdinalIgnoreCase))
            {
                List<string> rights = new List<string>();
                if ((record.GrantedAccess & NativeMethods.PROCESS_VM_READ) != 0) rights.Add("PROCESS_VM_READ");
                if ((record.GrantedAccess & NativeMethods.PROCESS_VM_WRITE) != 0) rights.Add("PROCESS_VM_WRITE");
                if ((record.GrantedAccess & NativeMethods.PROCESS_VM_OPERATION) != 0) rights.Add("PROCESS_VM_OPERATION");
                if ((record.GrantedAccess & NativeMethods.PROCESS_CREATE_THREAD) != 0) rights.Add("PROCESS_CREATE_THREAD");
                if ((record.GrantedAccess & NativeMethods.PROCESS_DUP_HANDLE) != 0) rights.Add("PROCESS_DUP_HANDLE");
                if ((record.GrantedAccess & NativeMethods.PROCESS_SUSPEND_RESUME) != 0) rights.Add("PROCESS_SUSPEND_RESUME");
                return string.Join("|", rights.ToArray());
            }

            return "0x" + record.GrantedAccess.ToString("X", CultureInfo.InvariantCulture);
        }

        private double ScoreConfidence(ObjectHandleRecord record, bool processSuspicious, bool objectSuspicious, bool protectedTargetHandle, bool writableOrExecutableSection, SignatureVerificationResult signature)
        {
            double score = 0.45;
            if (processSuspicious) score += 0.15;
            if (objectSuspicious) score += 0.15;
            if (protectedTargetHandle) score += 0.15;
            if (writableOrExecutableSection) score += 0.1;
            if (signature == null || !signature.IsTrusted) score += 0.1;
            if (HasRecentSignal("UntrustedDriverDropped") || HasRecentSignal("ShortLivedDriverFileDeleted") || HasRecentSignal("Vulnerable")) score += 0.1;
            if (HasRecentSignal("PrivateExecutableMemory") || HasRecentSignal("RwxPrivateMemory")) score += 0.1;
            return Math.Min(0.99, score);
        }

        private static EventSeverity SeverityFromConfidence(double confidence)
        {
            if (confidence >= 0.9) return EventSeverity.Critical;
            if (confidence >= 0.7) return EventSeverity.High;
            return EventSeverity.Medium;
        }

        private static string ActionForRecord(ObjectHandleRecord record, bool protectedTargetHandle, bool writableOrExecutableSection)
        {
            if (protectedTargetHandle) return "ProcessOpenedProtectedTarget";
            if (record.ObjectType.Equals("Device", StringComparison.OrdinalIgnoreCase)) return "SuspiciousDeviceObjectHandle";
            if (record.ObjectType.Equals("Section", StringComparison.OrdinalIgnoreCase)) return writableOrExecutableSection ? "WritableExecutableSectionHandle" : "SuspiciousSectionHandle";
            if ((record.ObjectName ?? string.Empty).StartsWith("\\Device\\NamedPipe", StringComparison.OrdinalIgnoreCase)) return "SuspiciousNamedPipeHandle";
            if (record.ObjectType.IndexOf("Port", StringComparison.OrdinalIgnoreCase) >= 0) return "SuspiciousAlpcPortHandle";
            return "SuspiciousCommunicationHandle";
        }

        private string GetOrCreateCase(string key, int sourcePid, int targetPid, string reason)
        {
            CommunicationCase existing;
            if (_cases.TryGetValue(key, out existing) && DateTime.UtcNow.Subtract(existing.LastUpdatedUtc) <= CorrelationWindow)
            {
                existing.LastUpdatedUtc = DateTime.UtcNow;
                return existing.CaseId;
            }

            string caseId = "KCOMM-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            CommunicationCase created = new CommunicationCase
            {
                CaseId = caseId,
                SourceProcessId = sourcePid,
                TargetProcessId = targetPid,
                CreatedUtc = DateTime.UtcNow,
                LastUpdatedUtc = DateTime.UtcNow,
                EvidenceFolder = GetCaseFolder(caseId),
                Reason = reason
            };
            Directory.CreateDirectory(created.EvidenceFolder);
            _cases[key] = created;
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
                string path = Path.Combine(folder, "kernel-communication-case.jsonl");
                lock (_caseWriteLock)
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

        private IEnumerable<string> EnumerateDosDeviceNames()
        {
            StringBuilder builder = new StringBuilder(65536);
            int length = NativeMethods.QueryDosDevice(null, builder, builder.Capacity);
            if (length <= 0)
            {
                yield break;
            }

            string all = builder.ToString();
            foreach (string item in all.Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries))
            {
                yield return item;
            }
        }

        private bool HasRecentSignal(string term)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            return _recentSignals.Any(s => s.TimestampUtc >= cutoff &&
                                           ((s.Category ?? string.Empty).IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            (s.Action ?? string.Empty).IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            (s.Description ?? string.Empty).IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            (s.Path ?? string.Empty).IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0));
        }

        private string SummarizeRecentSignals(int processId)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            return string.Join(" || ", _recentSignals
                .Where(s => s.TimestampUtc >= cutoff && (!s.ProcessId.HasValue || processId == 0 || s.ProcessId.Value == processId || IsRelevantSignal(s)))
                .Select(s => s.Summary)
                .Take(12)
                .ToArray());
        }

        private string SummarizeRecentPaths()
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            return string.Join(" | ", _recentSignals
                .Where(s => s.TimestampUtc >= cutoff && !string.IsNullOrWhiteSpace(s.Path))
                .Select(s => s.Path)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .ToArray());
        }

        private string SummarizeRecentMemoryFindings()
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            return string.Join(" || ", _recentSignals
                .Where(s => s.TimestampUtc >= cutoff &&
                            ((s.Action ?? string.Empty).IndexOf("Memory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             (s.Action ?? string.Empty).IndexOf("Private", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             (s.Action ?? string.Empty).IndexOf("Mapped", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             (s.Description ?? string.Empty).IndexOf("memory", StringComparison.OrdinalIgnoreCase) >= 0))
                .Select(s => s.Summary)
                .Take(8)
                .ToArray());
        }

        private void CleanupRecentSignals()
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            while (_recentSignals.TryPeek(out RecentSignal signal) && signal.TimestampUtc < cutoff)
            {
                RecentSignal ignored;
                _recentSignals.TryDequeue(out ignored);
            }

            foreach (KeyValuePair<int, DateTime> pair in _recentDeviceProcessIds.ToArray())
            {
                if (pair.Value < cutoff)
                {
                    DateTime ignored;
                    _recentDeviceProcessIds.TryRemove(pair.Key, out ignored);
                }
            }

            foreach (KeyValuePair<int, DateTime> pair in _recentTargetProcessIds.ToArray())
            {
                if (pair.Value < cutoff)
                {
                    DateTime ignored;
                    _recentTargetProcessIds.TryRemove(pair.Key, out ignored);
                }
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

        private ProcessIdentity QueryProcessIdentity(int processId)
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
                            return new ProcessIdentity
                            {
                                ProcessId = processId,
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

            return new ProcessIdentity
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

        private SignatureVerificationResult GetSignature(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return AuthenticodeVerifier.VerifyFile(path);
            }

            return _signatureCache.GetOrAdd(path, AuthenticodeVerifier.VerifyFile);
        }

        private static bool IsSuspiciousDeviceName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return false;
            }

            string[] terms =
            {
                "iqvw", "nal", "gdrv", "capcom", "dbutil", "rtcore", "winio", "eneio", "asrdrv",
                "mhyprot", "msio", "inpout", "physmem", "mapmem", "pmem", "kprocesshacker", "procexp"
            };

            foreach (string term in terms)
            {
                if (name.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsUnknownDeviceObject(ObjectHandleRecord record)
        {
            if (!record.ObjectType.Equals("Device", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string name = record.ObjectName ?? string.Empty;
            if (IsSuspiciousDeviceName(name) || LooksRandomizedName(LeafName(name)))
            {
                return true;
            }

            string lower = name.ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(lower) || !lower.StartsWith("\\device\\", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string[] commonPrefixes =
            {
                "\\device\\afd",
                "\\device\\cdrom",
                "\\device\\condrv",
                "\\device\\harddisk",
                "\\device\\ip",
                "\\device\\keyboardclass",
                "\\device\\ksecdd",
                "\\device\\lanmanredirector",
                "\\device\\mailslot",
                "\\device\\mountpointmanager",
                "\\device\\mouclass",
                "\\device\\mup",
                "\\device\\namedpipe",
                "\\device\\netbios",
                "\\device\\nsi",
                "\\device\\null",
                "\\device\\tcp",
                "\\device\\tdx",
                "\\device\\udp",
                "\\device\\volmgr"
            };

            foreach (string prefix in commonPrefixes)
            {
                if (lower.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsUnusualSectionName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return false;
            }

            string lower = name.ToLowerInvariant();
            if (lower.IndexOf("\\windows\\sharedsection") >= 0 ||
                lower.IndexOf("\\sessions\\") >= 0 && lower.IndexOf("\\base_named_objects\\") < 0)
            {
                return false;
            }

            return LooksRandomizedName(LeafName(name)) ||
                   lower.IndexOf("shared") >= 0 ||
                   lower.IndexOf("map") >= 0 ||
                   lower.IndexOf("aegis2") >= 0 ||
                   lower.IndexOf("iqvw") >= 0 ||
                   lower.IndexOf("loader") >= 0;
        }

        private static bool LooksRandomizedName(string name)
        {
            string leaf = LeafName(name);
            if (string.IsNullOrWhiteSpace(leaf) || leaf.Length < 8)
            {
                return false;
            }

            int letters = 0;
            int digits = 0;
            int separators = 0;
            int vowels = 0;

            foreach (char c in leaf)
            {
                if (char.IsLetter(c))
                {
                    letters++;
                    if ("aeiouAEIOU".IndexOf(c) >= 0)
                    {
                        vowels++;
                    }
                }
                else if (char.IsDigit(c))
                {
                    digits++;
                }
                else if (c == '-' || c == '_' || c == '{' || c == '}')
                {
                    separators++;
                }
            }

            bool guidLike = leaf.IndexOf('{') >= 0 || leaf.Count(c => c == '-') >= 3;
            bool mixedDense = letters >= 4 && digits >= 3 && separators <= 2;
            bool lowVowelLong = letters >= 8 && vowels <= 1 && digits >= 1;
            return guidLike || mixedDense || lowVowelLong;
        }

        private static string LeafName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return name;
            }

            int slash = name.LastIndexOf('\\');
            return slash >= 0 && slash + 1 < name.Length ? name.Substring(slash + 1) : name;
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

        private sealed class ObjectHandleRecord
        {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string ProcessPath { get; set; }
            public int ParentProcessId { get; set; }
            public string ObjectType { get; set; }
            public string ObjectName { get; set; }
            public uint GrantedAccess { get; set; }
            public ulong HandleValue { get; set; }
            public int TargetProcessId { get; set; }
        }

        private sealed class RecentSignal
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

        private sealed class ProcessIdentity
        {
            public int ProcessId { get; set; }
            public int ParentProcessId { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
        }

        private sealed class CommunicationCase
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
